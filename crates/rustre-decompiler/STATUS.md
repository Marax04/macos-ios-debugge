# STATUS — rustre-decompiler

> **Regole di questo file** (utente, 2026-08-18)
> 1. Ogni numero è **misurato**, mai stimato. Se una cosa non è stata misurata,
>    si scrive che non lo è stata.
> 2. **Non si toglie mai niente.** Si aggiunge in coda. Quando un dato viene
>    superato, la riga vecchia resta con la sua data e sotto compare la nuova.
> 3. Si scrive **ogni progresso e ogni regressione**, inclusi i tentativi
>    falliti e le correzioni di rotta. La lunghezza non è un problema.
> 4. Ogni numero riporta lo **snapshot** da cui viene (`runs/<label>`), perché
>    `out/` non è un oracolo: più agenti lo rigenerano in parallelo.

---

## Obiettivo dichiarato dall'utente (2026-08-18)

- **Path B unico**, con **tutta la catena di crate usata**.
- **0 `goto` e 0 `JUMPOUT`.**
- Livello **enterprise**, superiore a IDA Pro / Hex-Rays.

---

# Round 1 — 2026-08-18 — Audit della catena e baseline

## 1.1 Diagnosi centrale

**Il decompilatore non manca di capacità: manca di cablaggio.** Tre misure.

### Copertura API della catena

6573 elementi pubblici nei 18 crate della catena; 144 riferimenti qualificati
dal decompilatore; **≤13,9%** contando come "usato" ogni metodo che potrebbe
collidere per nome (quindi è un *tetto*, non una stima centrale).

| crate | inutilizzati / totale | note |
|---|---|---|
| `analysis-xref` | 411 / 465 | intero sottosistema call-graph/reachability |
| `analysis-vtable` | 384 / 414 | **7,2%**, peggiore del workspace |
| `analysis-cfg` | 355 / 400 | loop forest, frontiere di dominanza, jump table |
| `analysis-type` | 355 / 403 | `ParameterTypeInference`, `InferredSignature` |
| `analysis-dataflow` | 350 / 404 | **solo 4 nomi raggiunti in totale** |
| `il-passes` | 341 / 387 | 11,9% |
| `decompiler-type` | 352 / 446 | |

Metodo: conteggio grep di `pub fn|struct|enum|trait` deduplicato per nome, con
misura doppia (qualificata = limite inferiore, larga = limite superiore).
Verificato che **non esistono percorsi di re-export nascosti**: `rustre-il`
non ri-esporta i fratelli, `rustre-core` ri-esporta solo `events`/`knowledge`/`db`.

### Duplicazione monolite ↔ crate

**168 funzioni con nome identico** fra `lib.rs` (44357 righe) e i crate della
catena. Tolte le banali (`new`, `len`, `fmt`…), restano riscritture sostanziali:

`construct_ssa` · `compute_idoms` · `compute_dominance_frontiers` ·
`find_back_edges` · `analyze_stack_frame` · `detect_calling_convention` ·
`detect_jump_table` · `collect_call_sites` · `dead_vars` · `alias_sets` ·
`emit_switch` · `emit_while` · `build_cfg` · `detect_from_instructions`

Il monolite ha riscritto a mano la costruzione SSA, i dominatori, le frontiere
di dominanza, i back-edge, l'analisi dello stack frame, il rilevamento della
convenzione di chiamata e delle jump table.

### Gate d'ambiente

**135 gate `RUSTRE_*` distinti** nel solo decompilatore. I principali sono
spenti di default: `RUSTRE_HLIL`, `RUSTRE_MLIL_SSA`, `RUSTRE_IL_PASSES`,
`RUSTRE_VSA_JUMPTABLES`, `RUSTRE_DATAFLOW_MLIL`, `RUSTRE_VTABLE_LABELS`,
`RUSTRE_LIBSIG_ARITY`, `RUSTRE_EMIT_DATA`.

## 1.2 Correzione a una lettura iniziale sbagliata (mia)

Il primo grep (`rustre_analysis_vsa::`, `rustre_analysis_dataflow::`,
`rustre_analysis_vtable::`) dava **0** e ne avevo concluso "linkati e mai
chiamati". **Falso negativo mio**: `analysis_bridge.rs` (1228 righe) li importa
con alias (`use rustre_analysis_vsa as vsa;` ecc.).

Il fatto vero è diverso e migliore: i crate **sono chiamati ma INERTI** — o il
risultato finisce in `ctx.annotations` (che `DecompilerContext::finish` scarta),
o il consumatore esiste dietro un gate spento. Il commento nel sorgente lo dice
già: «il crate non era scollegato, era INERTE».

Seconda correzione mia nello stesso round: avevo scritto che i risultati VSA
venivano *buttati*. Rifatto il conteggio senza dipendere dalla formattazione
(`ctx.annotations` e `.get(...)` sono spesso su righe diverse), le chiavi mai
rilette sono quasi tutte **contatori diagnostici**; i payload veri
(`vsa_jump_table_targets`, `vsa_resolved_calls`, `typerecov_types`) **sono
consumati**. Unica eccezione sostanziale: `mlil_ssa`, scritta e mai riletta.

## 1.3 La pipeline dichiarata non è quella eseguita

- **HLIL è un ramo morto in produzione.** `lib.rs:28560`, gate
  `hlil_experimental || RUSTRE_HLIL`, entrambi default OFF
  (`lib.rs:506,516`). **Verificato sullo snapshot fresco: 0 file `.hlil.c` su
  11342.** (I `.hlil.c` presenti in `out/` sono del 23-07, da una run col flag.)
- Il C che le metriche leggono nasce da `emit_structured_code`
  (`lib.rs:19133`) su blocchi costruiti da
  `build_cfg_from_instructions_with_tables(instructions: &[Instruction])`
  (`lib.rs:811`) — **disassemblato testuale**: i leader di blocco sono trovati
  con `ins.mnemonic.to_lowercase()` e `parse_hex_target(ins.operands.trim())`.
- **MLIL è un produttore di annotazioni, non un IR di emissione.**
  `build_mlil_cfg` (`lib.rs:27686`) gira sempre, ma raggiunge il C per **un
  solo canale**: i tipi scritti in `ctx.variables` dal type-recovery (~27800).
  `MlilAnalyzer` (default ON, `lib.rs:28460`) produce solo annotazioni.
- **La SSA MLIL esiste, è completa, ed è spenta.** `mlil_ssa.rs` ha frontiera di
  dominanza iterata, piazzamento PHI, def-use, const-prop.
  `MlilFunction::into_ssa()` è chiamata solo dietro `RUSTRE_MLIL_SSA=1`
  (`lib.rs:28502`), default OFF. Quello che gira su path A è
  `ssa_split::split_versions` (`lib.rs:19368`), un rinominatore **testuale** di
  live-range: niente PHI, niente dominanza. **Non è SSA.**
  Il repo lo ammette a `lib.rs:28473`: «`into_ssa()` esiste e funziona ma il suo
  risultato non arrivava mai a valle: l'unico chiamante BUTTA la forma SSA».
- **Il pass manager IL: 36 pass → 9 registrati → gate spento → 0 eseguiti.**
  Registrazione unica in `optimize_lifted_llil` (`lib.rs:25969`, PassManager
  `26080-26094`), chiamata solo da `lib.rs:27657` dietro `RUSTRE_IL_PASSES`
  (default OFF, `lib.rs:25739`).
  Mai istanziati (27): `GlobalValueNumberingPass`, `Mem2RegPass`,
  `CopyPropagationPass`, `DeadStoreEliminationPass`, `DevirtualizationPass`,
  `RedundantLoadEliminationPass`, `StoreLoadForwardingPass`,
  `IntegerRangeAnalysisPass`, `TailCallOptimizationPass`, … Più moduli interi
  mai referenziati: `ssa.rs`, `gvn2.rs`, `dominators.rs`, `alias.rs`,
  `switch_detection.rs`, `type_recovery_pass.rs`, `optimization_pipeline.rs`,
  `pass_dependency_graph.rs`, `pass_metrics.rs`, `constant_propagation.rs`.

## 1.4 Perché "solo path B" **oggi** sarebbe una regressione

Divario misurato sul corpus (snapshot 07-23, l'unico che contiene i `.hlil.c`):

| difetto | path A | path B |
|---|---|---|
| `var_tmp0` (temporanei non propagati) | **0** | 9497 |
| `goto loc_` | **0** | 7447 |
| `var_sp` (prologo simulato) | **0** | 6382 |
| `flag_zf` (flag non fusi) | **0** | 2151 |
| `JUMPOUT` | 25 | 1909 |
| file con `sub_X()` senza argomenti | 6074 | 7029 |

Confronto qualitativo sulla stessa funzione (`__tmainCRTStartup`):

| | path A | path B |
|---|---|---|
| firma | `__int64 __fastcall __tmainCRTStartup()` | `void fn_140001010()` |
| chiamate | `malloc(v3)`, `memcpy(...)`, `strlen(v3)`, `_amsg_exit(31)` | `sub_1400027C0()` — **nomi e argomenti persi** |
| flag | fusi in `if (i == result)` | esposti (`flag_zf`, `flag_sf`, `flag_of`) |
| prologo | rimosso | simulato: 8 `var_sp = var_sp - 8` in testa |
| flusso | strutturato | `JUMPOUT` + 7 `goto loc_` irraggiungibili |

Il nome nasce da `format!("fn_{:x}", mlil.entry.as_u64())` a
`rustre-il-hlil/src/lib.rs:2358`: la tabella dei simboli non entra mai.

**Ma le 7 cose che mancano a path B sono 7 crate oggi inutilizzati**, quindi
portare path B alla parità *è* usare tutta la catena. Stesso lavoro, ordine
diverso: si commuta alla fine, con la misura in mano.
**Ironia utile:** path B ha la logica MIGLIORE — è lui che definisce i simboli
dati (`prepend_hlil_externs` → `data_symbol_definitions`, `lib.rs:11794`),
risolve i puntatori a codice (`resolve_hlil_code_pointers`, `lib.rs:20061`) e
ritipizza le firme void (`lib.rs:20260`) — e nessuno la vede.

## 1.5 Baseline misurata — snapshot `runs/base_0818`

Driver ricostruito il 2026-08-18 (il precedente era **stale**: `.exe` del 15-08
04:11 contro `lib.rs` delle 19:59 — `measure.sh` avrebbe rifiutato di girare).

| metrica | valore | note |
|---|---|---|
| file emessi | 11342 | combacia con la misura del 14-08 in CLAUDE.md |
| arity vs prototipi | **122/135** (90,37%) | 6 OVER, 7 UNDER |
| fidelity 16 pubblicati | **14/16** | ⚠ **REGRESSIONE** da 15/16 |
| **behaviour** | **15/63 (23,8%)** | l'unica metrica dell'obiettivo vero |
| ↳ LINK_FAIL | 19 | classe più grande |
| ↳ CRASH | 12 | |
| ↳ DIVERGE | 11 | |
| ↳ COMPILE_FAIL / NOT_EMITTED | 3 / 3 | |
| `goto` (ogni forma) | **0** su 11342 file | già meglio di Hex-Rays |
| `JUMPOUT` | **18**, in 12 file | tutti nei bucket C# |
| call site incoerenti *(metrica nuova)* | 9756 OVER, 6042 UNDER | su 10330 definizioni |
| dichiarazioni implicite | ~28% dei file (campione 60) | invisibili a `-w` |

⚠ **La scala di `behaviour` è cambiata e va detto**: 12 funzioni il 23-07
(5 AGREE, 41,7%), **63** dal 15-08 (15 AGREE, 23,8%). Il "7/14" scritto in
CLAUDE.md è la vecchia scala. Il tasso è *sceso* perché il campione più largo ha
smesso di essere gentile — che è ciò che una metrica deve fare.

Cause nominate negli esiti LINK_FAIL: `runtime_panicIndex: external`,
`__rustc____rust_no_alloc_shim_is_unstable_v2: external`,
`sub_140087E14: INTERIOR_ADDRESS (inside emitted 0x140087c8a)`.

## 1.6 Difetti trovati, con causa isolata

### (a) Regressione fedeltà 15/16 → 14/16

`fidelity.sh` ha **un solo commit** dalla nascita → **non** è un cambio di
harness, è una regressione reale. 14 snapshot storici leggono 15/16; solo
`wip_0815` (15-08) e `base_0818` leggono 14/16.

Funzione: `_pei386_runtime_relocator`, da `arity 0` a **4 parametri fantasma**.

**Causa:** il decompilatore si contraddice da solo —
```c
__int64 __fastcall __mingw_GetSectionCount() { …   // definito con 0 parametri
__mingw_GetSectionCount(a1, a2, a3, a4);           // chiamato con 4
```
La regola D9 in `win64_param_regs_live_in` (`lib.rs:2450`) legge i 4 argomenti
al call site, deduce `rcx/rdx/r8/r9` vivi in ingresso, non trova chi li
definisca nel corpo e li **promuove a parametri del chiamante**. L'errore si
propaga **verso l'alto**. La guardia di contiguità impedisce di *creare* il
primo parametro ma non di *estenderlo*; il commento in-source lo dice già:
«la sola regola che può creare un parametro che il corpo non legge MAI».

Nota: il repo ha **un solo commit** (`ed3ab0d`, 14-08, "Initial commit") — la
storia precedente è schiacciata, quindi l'attribuzione via git non è possibile.

### (b) I 18 `JUMPOUT` rompono il link — non sono estetica

`JUMPOUT` **non è definito** in `ida_defs.h` (35 righe, 0 occorrenze).
Provato eseguendo il compilatore:
```
gcc -std=gnu89 -fsyntax-only -w                → exit 0        (passa)
gcc -Werror=implicit-function-declaration      → error: implicit declaration
                                                  of function 'JUMPOUT'
```
Tutti e 18 hanno **la stessa forma**: salto in coda attraverso un puntatore.
```
8 × JUMPOUT(ptr->field_18);      2 × JUMPOUT(result->field_48);
2 × JUMPOUT(ptr->field_38);      2 × JUMPOUT(ptr->field_30);
2 × JUMPOUT(*v6);                2 × JUMPOUT(*(result + 32));
```
**Correzione individuata:** la guardia a `lib.rs:17939` accetta solo
identificatori semplici (`op.chars().all(is_ascii_alphanumeric || '_')`) ed
esclude esplicitamente gli operandi di memoria. Estenderla emettendo `({op})()`
li converte in `return (ptr->field_18)();` — **semanticamente esatto**: un salto
a un puntatore in coda *è* una tail call.
**Verificato a valle** (per non trasformare un difetto in un altro):
`cast_indirect_call_targets` (`lib.rs:8632`) documenta e testa già
`(ptr->field_30)();` → `((__int64 (*)())(ptr->field_30))();` e
`(*v2)();` → `((__int64 (*)())(*v2))();`, con test anche per la forma dentro
`return` (`lib.rs:39522`).

Un caso si chiude ancora meglio:
```c
v6 = &sub_140052130;  return JUMPOUT(*v6);   →   return sub_140052130();
```
Il target è **staticamente noto**: lo risolve una propagazione di costanti,
cioè `ConstantPropagationPass`/`CopyPropagationPass` di `il-passes` — mai
eseguiti. Qui "0 JUMPOUT" e "usa i crate" coincidono.

### (c) ~28% dei file chiama funzioni mai dichiarate

Campione di 60 file: **60/60 passano** con `-w`, **17/60 falliscono** con
`-Werror=implicit-function-declaration`. Estrapolato ~3200 file su 11342 —
parente stretto del 49% che non linka. Tre classi distinte:

1. **Forward declaration mancanti per i nomi CRT/WinAPI risolti**: `fpreset`,
   `EnterCriticalSection`, `LeaveCriticalSection`, `fprintf`, `vfprintf`,
   `signal`, `_amsg_exit`, `_cexit`, `__set_app_type`, `__p__commode`,
   `__p___initenv`, `_initterm`, `_crt_atexit`, `__mingw_setusermatherr`.
   Filtro a `lib.rs:148` di `emit_callee_forward_decls`:
   ```rust
   let crt_accessor = name.starts_with("__p_") || name.starts_with("___")
                   || code.contains(&format!("__imp_{name}"));
   if name.starts_with('_') && crt_accessor { continue; }
   ```
   Già tarato in entrambe le direzioni dal precedente autore: dichiararli dà
   «conflicting types», non dichiararli dà «undeclared identifier». La via
   d'uscita è dichiararli con la firma **giusta** — vedi §1.7.
2. **Intrinseci assenti dal prelude**: `__readgsqword`, `_InterlockedExchange64`.
   Ironia: `__readgsqword` è emesso *apposta* da un pass di ricompilabilità e
   poi non è dichiarato — il pass si annulla da solo.
3. **50 `push(...)` in 32 file**: mnemonici x86 emessi come chiamate C.
   Forma tipica: `push(result); result = 0; *(__int64 *)rsp = result;`.
   Appartiene alla famiglia dello stack frame (vedi §1.8 step 1).

### (d) `measure.sh` esegue `behavior.py` due volte

```bash
python behavior.py "$DEST/out"        > behavior.txt    # ~34 min
python behavior.py "$DEST/out" --json > behavior.json   # altri ~30 min
```
La stessa analisi (compilare, linkare ed eseguire 63 funzioni contro
2180–3377 oggetti per bucket) è ripetuta identica per cambiare formato.
**Ogni misura completa costa ~62 minuti invece di ~32.** Prova: in `wip_0815`
`behavior.txt` è delle 20:03:48 e `behavior.json` delle 20:33:55; in
`base_0818` `behavior.json` risulta creato (a 0 byte) alle 11:01:00, cioè
quando la seconda invocazione è partita.
**Correzione:** calcolare una volta sola e derivare il testo dal JSON.
Impatto: dimezza il tempo di **ogni** iterazione futura.

## 1.7 L'occasione più economica del repo — zero righe di codice

`published_lib_arity` (`lib.rs:13803`) consulta `LibrarySignatureDb` di
`rustre-analysis-type`, popolato da **`mingw_runtime_sigs.rs`: 154 firme
mingw-w64/libgcc estratte meccanicamente dagli header**, con `header:riga`
annotata per ogni voce. Il file è generato da `tools/gen_runtime_prototypes.py`
e non è usato da nessuno oltre al proprio `mod`.

La funzione **esce subito**:
```rust
if !matches!(std::env::var("RUSTRE_LIBSIG_ARITY").as_deref(),
             Ok("1") | Ok("true")) { return None; }
```
Ecco perché `_Unwind_FindEnclosingFunction` esce con **0 parametri** mentre la
firma corretta (**1 parametro**, `unwind.h:183`) è nel database che il
decompilatore *effettivamente consulta*. CLAUDE.md descrive quella funzione come
«perfettamente consistente e uniformemente sbagliata»: la risposta giusta era
già in casa.

Il commento in-source chiede esplicitamente che la promozione a default-ON sia
fatta «col numero in mano (`measure.sh`), non per simmetria». **È esattamente
l'esperimento da eseguire, e non richiede di scrivere codice.**

## 1.8 Coda di lavoro (ordinata per costo crescente)

| # | mossa | costo | bersaglio |
|---|---|---|---|
| 0 | `measure.sh`: una sola esecuzione di `behavior.py` | ~5 righe | **dimezza ogni iterazione futura** |
| 1 | `RUSTRE_LIBSIG_ARITY=1` | **zero codice** | 7 UNDER di arity, `_Unwind_*` |
| 2 | `RUSTRE_VSA_JUMPTABLES=1` | **zero codice** | switch recovery, chiamate indirette |
| 3 | `JUMPOUT` → tail call (`lib.rs:17939`) | 1 riga | **requisito utente: 0 JUMPOUT** |
| 4 | parametri fantasma (`win64_param_regs_live_in`) | — | regressione 15/16 → 14/16 |
| 5 | installare `callsite_consistency.py` in `measure.sh` | — | 15798 incoerenze oggi invisibili |
| 6 | prologo/epilogo su path B via `analysis-fn` | — | 6382 `var_sp` + 50 `push()` |
| 7 | `il-passes` CopyProp/GVN su path B | — | 9497 `var_tmp0` |
| 8 | SSA MLIL accesa | — | 2151 `flag_zf` |
| 9 | `MlilCallAnalysis` / `ParameterTypeInference` | — | argomenti e firme di path B |
| 10 | `hlil_structuring` / `LoopStructurer` / `LoopForest` | — | 7447 `goto` di path B |
| 11 | `flirt-apply` su path B | — | nomi di libreria |
| 12 | commutazione a path B **quando supera A** | — | obiettivo finale |

### Design già chiuso per lo step 6 (prologo su path B)

- LLIL ha `Push { size, src }` / `Pop { dest, size }` di prima classe
  (`rustre-arch-x86/src/lift.rs:9481, 9501`) — l'identità del push **esiste**.
- `rustre-il-mlil::calling_convention_db` ha già
  `callee_saved: vec![RBX, RBP, R12, R13, R14, R15]` per win64 (riga 321) —
  mai usato.
- Il lift MLIL **espande** il push in `sp = sp - 8; *sp = v`, distruggendo
  l'identità prima che qualcuno possa eliderla → intervenire a livello **LLIL**,
  prima di `build_mlil_cfg` (`lib.rs:27686`).
- `rustre-analysis-fn::analyze_stack_frame(addr, &[(Address, LlilInstruction)])`
  esiste, è testato, **non lo chiama nessuno**; il decompilatore usa una copia
  riscritta a mano su stringhe (`signature_recovery::analyze_stack_frame`, usata
  da `pass_pipeline.rs:728` via `RawMnemonicView` di mnemonici testuali).
- Path A elide il prologo con `collapse_stack_frame` (`lib.rs:17961`), che
  filtra a mano `rsp = rsp ± N`.
- Guardia fail-safe prevista: se il conteggio dei `Push` non combacia con quello
  dei `Pop`, **non eliminare nulla**.

## 1.9 Stato operativo di fine round

- **Zero sorgenti modificati** in tutto il round: `measure.sh` prende
  l'impronta dell'albero **prima e dopo**, e un file mosso invalida il run.
  Verificato che l'impronta copre **solo i `.rs`** (`measure.sh:66`) più gli
  harness e il driver: un `.md` come questo si può scrivere a misura in corso.
- `runs/base_0818` completata per `arity`, `fidelity`, `behaviour`;
  `sig_sanity`/`cross_build`/`unresolved`/`metrics` ancora in coda al momento
  della scrittura (attesa dovuta alla doppia esecuzione descritta in §1.6d).
- `callsite_consistency.py` scritto e validato, **non ancora installato** nel
  corpus (installarlo cambia l'impronta dell'harness → richiede ri-baseline,
  comportamento previsto e documentato in CLAUDE.md).

---

# Round 2 — 2026-08-18 — Progettazione della mossa 0 (dimezzare il costo della misura)

## 2.1 La doppia esecuzione è SISTEMICA, ma la correzione non dev'esserlo

`measure.sh` invoca **ogni** harness due volte, una per il testo e una per il
JSON. Righe: 142/143 (`fidelity_arity.py`), 157/158 (`behavior.py`),
168/169 (`sig_sanity.py`), 181/182 (`cross_build.py`), 195/196
(`unresolved.py`).

**Misurato dai timestamp di `runs/base_0818`**, non dedotto:

| harness | costo della seconda esecuzione |
|---|---|
| `fidelity_arity.py` | `arity.txt` 10:27:41 → `arity.json` 10:27:42 = **1 secondo** |
| `sig_sanity.py` | ~1 secondo |
| `cross_build.py` | ~1 secondo |
| `unresolved.py` | ~1 secondo |
| **`behavior.py`** | `behavior.txt` 11:01:00 → `behavior.json` ancora in corso alle 11:10 = **~30 minuti** |

**Decisione: correggere SOLO `behavior.py`.** Sistemare tutti e cinque "per
coerenza" toccherebbe cinque file e cinque impronte di harness per guadagnare
quattro secondi. È lo stesso principio che il repo applica al gate
`RUSTRE_LIBSIG_ARITY`: *«la promozione va fatta col numero in mano, non per
simmetria»*.

## 2.2 Causa letta nel codice, non supposta

In `behavior.py::main` tutto il lavoro costoso — `build_reference`,
`build_bucket`, `symbol_tables`, il link della chiusura transitiva e
l'esecuzione — avviene prima della riga 569, dove **solo allora** si dirama su
`a.json` per scegliere il formato di stampa. Le due invocazioni fanno lavoro
identico e ne buttano metà.

## 2.3 Patch progettata (non ancora applicata: misura in corso)

**`behavior.py`** — nuovo argomento `--json-out PATH`: il payload JSON (già
costruito alle righe 569-578, comprensivo di `functions` per-funzione) viene
scritto su file, mentre il testo continua su stdout. Il ramo `--json` esistente
resta intatto per compatibilità.

**`measure.sh:157-158`** — due invocazioni diventano una:
```bash
python "$CORPUS/behavior.py" "$DEST/out" --json-out "$DEST/behavior.json" \
       > "$DEST/behavior.txt" 2>&1
```

Effetto atteso: misura completa da ~62 a ~32 minuti. **Da verificare misurando**,
non dando per scontato.

⚠ `behavior.py` è nell'impronta degli harness (`measure.sh:97`), quindi il primo
`--compare` successivo riporterà `changed (harness differs)`. È il comportamento
previsto e documentato in CLAUDE.md, **non** una regressione.

## 2.4 Round 2 — cosa NON è stato fatto e perché

Nessun sorgente modificato: `runs/base_0818` era ancora in esecuzione sulla
seconda invocazione di `behavior.py`. Il vincolo dell'impronta vale per i `.rs`,
ma `behavior.py` e `measure.sh` non vanno toccati mentre `measure.sh` gira
(bash rilegge lo script durante l'esecuzione).

---

# Round 3 — 2026-08-18 — Verifica preventiva della mossa 1 (`RUSTRE_LIBSIG_ARITY`)

## 3.1 Perché una verifica preventiva

Una misura completa costa ~62 minuti (§2.1). Prima di spenderli, controllare che
l'esperimento **possa** muovere qualcosa: quante delle 136 funzioni misurate da
`fidelity_arity.py` sono coperte dalle 139 firme di
`rustre-analysis-type/src/mingw_runtime_sigs.rs`?

Nota di metodo: il primo tentativo ha dato «2 prototipi misurati», risultato
assurdo → **difetto nel mio parsing**, non nel dato. `prototypes.json` è
annidato (`{_provenance, prototypes}`), non piatto. Corretto e rimisurato.
Ennesima conferma che una misura nuova rivela prima un difetto in sé stessa.

## 3.2 Risultato: la copertura è quasi totale

| | valore |
|---|---|
| prototipi misurati (`prototypes.json`) | 136 |
| firme nel DB (`mingw_runtime_sigs.rs`) | 139 |
| **sovrapposizione** | **126 (92,6%)** |

E i cinque OVER della baseline (esclusa la regressione `_pei386_runtime_relocator`)
sono **tutti** nel DB:

```
OVER  _pthread_tryjoin:              want 2, got 4
OVER  pthread_cond_signal:           want 1, got 3
OVER  pthread_join:                  want 2, got 4
OVER  pthread_mutex_timedlock32:     want 2, got 4
OVER  pthread_rwlock_timedrdlock32:  want 2, got 4
```

Coperto anche `__acrt_iob_func`, che CLAUDE.md cita come il caso del parametro
`a2` fantasma presente in `sample7_cpp` e assente nelle altre 5 build.

## 3.3 ⚠ MA la misura sarebbe in parte TAUTOLOGICA — leggere prima di giudicare

`prototypes.json::_provenance` dichiara: *«mingw-w64 installed headers,
include_dir `C:\msys64\mingw64\include`, headers_scanned 2349»*.
`mingw_runtime_sigs.rs` dichiara: *«extracted mechanically from the installed
headers»*.

**Sono la stessa sorgente.** Accendere `RUSTRE_LIBSIG_ARITY` dà al decompilatore
le risposte estratte dagli stessi header da cui la metrica ricava la verità: per
quelle 126 funzioni l'arity salirebbe **quasi per costruzione**, e il
miglioramento del numero sovrastimerebbe il miglioramento reale di fedeltà.

Questo **non** rende l'esperimento sbagliato: la firma pubblicata *è* la
risposta corretta, e un decompilatore serio consulta le firme note esattamente
come IDA consulta le proprie type library. Rende sbagliato **giudicarlo su
`arity`**.

### Criteri di giudizio per la mossa 1

| metrica | come leggerla |
|---|---|
| `arity` (122/135) | attesa in salita, **circolare**: non è la prova |
| **`behaviour` (15/63)** | **il giudice vero**: firme giuste → link e chiamate giuste |
| `callsite_consistency` (9756 OVER / 6042 UNDER) | indipendente dagli header: **deve scendere** |
| `cross_build` | deve restare stabile |

Se `arity` sale e `behaviour` non si muove, è stato migliorato un numero e non il
decompilatore — lo stesso autoinganno che CLAUDE.md documenta con i 2233
parametri fantasma che lasciarono `check.sh` a 11143/11144.

---

# Round 4 — 2026-08-18 — Verifica preventiva della mossa 2, e riordino delle priorità

## 4.1 Il dubbio che ha innescato la verifica

Path A ha **0 `goto`** e **18 `JUMPOUT`** (§1.5). Se il rilevatore sintattico di
jump table funziona già, cosa aggiunge `RUSTRE_VSA_JUMPTABLES`?

## 4.2 Misura su `runs/base_0818`

| | valore |
|---|---|
| `switch` recuperati | **161** |
| file con `switch` | 131 |
| `case` totali | **1341** |
| **chiamate indirette opache** | **1363** |
| `JUMPOUT` | 18 |

**Il recupero sintattico delle jump table funziona già**: 161 switch, 1341 case.

## 4.3 Conseguenza 1 — la mossa 2 vale meno del previsto: RETROCESSA

`RUSTRE_VSA_JUMPTABLES` agisce sui siti di salto indiretto che
`build_vsa_cfg_from_mlil` scarta. Con 0 `goto` e 18 `JUMPOUT`, il **tetto
massimo su path A è 18 siti** — gli stessi che la mossa 3 (JUMPOUT → tail call)
chiude in modo più diretto e con una riga.

Nota: la parte VSA che risolve le **chiamate** indirette
(`apply_vsa_resolved_calls`, `lib.rs:9431`, chiamata da `lib.rs:19559`) è già
attiva di default e riscrive il testo quando VSA restringe un callee a
esattamente un indirizzo. Quella non è gated.

## 4.4 Conseguenza 2 — il vero bersaglio sono 1363 chiamate indirette opache

Ogni `((__int64 (*)())(x))()` è una chiamata di cui il decompilatore **non ha
saputo nominare il bersaglio**: rompe il grafo delle chiamate ed è una causa
plausibile dei 19 LINK_FAIL e degli 11 DIVERGE.

Classificazione misurata delle 1363:

| forma | quante | chi la risolverebbe |
|---|---|---|
| campo struct (`result->field_30`) | **272** | `analysis-vtable` + `VirtualCallResolver` (dispatch virtuale) |
| deref `*(…)` | 195 | `MlilAliasAnalysis` / propagazione costanti |
| locale semplice | ~896 | `IndirectCallResolver` VSA — già attivo, evidentemente insufficiente |
| simbolo dati `off_` | 0 | — |

Distribuzione per bucket: `sample7_cpp` 262, `sample10_cs` 214, `sample5_cs`
209, `sample9_go` 180, `sample4_go` 173, `sample3_rust`/`sample8_rust` 124,
bucket C ~15-16. **C++ e C# dominano** → è dispatch virtuale.

## 4.5 Conseguenza 3 — `analysis-vtable` RIVALUTATA AL RIALZO

Nel Round 1 l'avevo classificata come costosa e a lungo termine (nessun
consumatore esistente, e bloccata dietro il porting di `data_symbol_definitions`).
Resta vero il costo, ma ora ha un **bersaglio misurato**:

- **272 chiamate virtuali non risolte** (campo struct), concentrate nei bucket
  C++/C# dove il crate è pertinente;
- le vtable stanno in `.rdata`, quindi appartengono ai **7329 simboli dati
  "azionabili"** non materializzati che tengono il 49,2% dei file fuori dal link;
- è il crate col **peggior rapporto d'uso del workspace**: 384 inutilizzati su
  414 (7,2%), con RTTI, gerarchie, override map ed ereditarietà multipla tutti
  scritti e mai chiamati.

## 4.6 Coda di lavoro aggiornata (sostituisce l'ordine di §1.8 dalla voce 2 in poi)

| # | mossa | costo | bersaglio misurato |
|---|---|---|---|
| 0 | `measure.sh`: una sola esecuzione di `behavior.py` | ~5 righe | dimezza ogni iterazione |
| 1 | `RUSTRE_LIBSIG_ARITY=1` | zero codice | 5 OVER `pthread_*` + `__acrt_iob_func` — **giudicare su `behaviour`, non su `arity`** (§3.3) |
| 2 | `JUMPOUT` → tail call | 1 riga | 18 siti, **requisito utente 0 JUMPOUT** |
| 3 | parametri fantasma (`win64_param_regs_live_in`) | — | regressione 15/16 → 14/16 |
| 4 | `callsite_consistency.py` in `measure.sh` | — | 15798 incoerenze invisibili |
| 5 | **chiamate virtuali via `analysis-vtable`** | alto | **272 chiamate + classe `.rdata`** ⬆ salita di priorità |
| 6 | prologo/epilogo path B via `analysis-fn` | — | 6382 `var_sp` + 50 `push()` |
| 7 | `il-passes` CopyProp/GVN su path B | — | 9497 `var_tmp0` |
| 8 | SSA MLIL accesa | — | 2151 `flag_zf` |
| 9 | `MlilCallAnalysis`/`ParameterTypeInference` | — | argomenti e firme path B |
| 10 | `hlil_structuring`/`LoopStructurer` | — | 7447 `goto` path B |
| 11 | `flirt-apply` su path B | — | nomi di libreria |
| 12 | commutazione a path B quando supera A | — | obiettivo finale |
| — | ~~`RUSTRE_VSA_JUMPTABLES`~~ | zero codice | **retrocessa**: tetto 18 siti, coperti dalla mossa 2 |

---

# Round 5 — 2026-08-18 — Perché falliscono 48 funzioni su 63

## 5.1 Ripartizione delle cause (da `runs/base_0818/behavior.txt`)

| causa | occorrenze |
|---|---|
| `external` | **25** |
| **`DATA_NOT_EMITTED`** | **15** |
| «buffer contents differ after call» | 6 |
| `INTERIOR_ADDRESS` | 3 |

Simboli mancanti più frequenti:
`operator_delete_void___unsigned_long_long_` ×5, `runtime_panicIndex` ×3,
`operator_new_unsigned_long_long_` ×3,
`__rustc____rust_no_alloc_shim_is_unstable_v2` ×3, `sub_1400014C5` ×2,
`off_140004000` ×2, `_core__fmt__builders__DebugList___entry` ×2,
`__OFSUB` ×2.

## 5.2 Lettura

- **`DATA_NOT_EMITTED` (15) è la classe azionabile più grande.** È esattamente
  il fronte dei simboli dati che path A non materializza (ZERO definizioni)
  mentre path B ne definisce il 66%. **Conferma indipendente** che la direzione
  «path B» dell'utente è giusta: qui la si vede dalla metrica comportamentale,
  non dall'ispezione del codice.
- **`external` (25)** sono simboli genuinamente fuori dall'immagine
  (`runtime_panicIndex`, `operator_new/delete`, shim di rustc): non
  materializzabili: servirebbero stub. Da NON contare come difetto del
  decompilatore.
- **`INTERIOR_ADDRESS` (3)**: `sub_1400014C5: INTERIOR_ADDRESS (inside emitted
  0x1400014a0)` — chiamata a un indirizzo *dentro* una funzione già emessa.
  Difetto di **confine funzione**, classe a sé.
- «buffer contents differ» (6) sono i DIVERGE: il codice gira e produce il
  risultato sbagliato. Classe semantica, la più costosa da chiudere.

## 5.3 IDA-ismi emessi e mai definiti nel prelude

`ida_defs.h` (35 righe) definisce solo `__fastcall`, `__cdecl`, `__stdcall`,
`__thiscall`, `__noreturn`, `true`, `false`. Mancano:

| IDA-ismo | usato nel corpus | nel prelude |
|---|---|---|
| `JUMPOUT` | 18 | **no** |
| `__OFSUB` | **12** | **no** |

Entrambi sono emessi dal decompilatore stesso e poi non dichiarati → chiamata a
funzione implicita → passa `-fsyntax-only -w`, **non linka** (§1.6b).

`__OFSUB` è il flag di overflow di una sottrazione. Due correzioni, **non
alternative**:
1. **definirlo nel prelude** — sblocca il link subito ed è corretto: `ida_defs.h`
   fa parte del contratto di ricompilazione, come in IDA;
2. **fonderlo via** — 12 occorrenze significano che la fusione dei flag (feature
   già presente: `cmp/test/comi→branch`, ZF-da-ALU-composta) ha fallito 12
   volte. Questa è la correzione di fedeltà vera.

⚠ `ida_defs.h` è nell'impronta dei sorgenti (`measure.sh:67`): modificarlo
comporta una ri-baseline.

## 5.4 Ordine di attacco per muovere `behaviour` (15/63)

Ordinato per rapporto (funzioni sbloccate) / (costo):

1. **`__OFSUB` + `JUMPOUT` nel prelude** — 30 occorrenze di link rotto, costo
   quasi nullo. Da fare INSIEME alla mossa 2, che elimina i `JUMPOUT` alla
   fonte: se la mossa 2 riesce, resta solo `__OFSUB`.
2. **`DATA_NOT_EMITTED` (15)** — portare `data_symbol_definitions` da path B a
   path A, oppure (meglio, e nella direzione dell'utente) far crescere path B.
3. **`INTERIOR_ADDRESS` (3)** — confini di funzione.
4. **DIVERGE (6-11)** — semantica: la classe più costosa, da affrontare per
   ultima e caso per caso.
5. `external` (25) — **non è un difetto del decompilatore**: contarli a parte
   per non inquinare il giudizio.

---

# Round 6 — 2026-08-18 — Un DIVERGE sezionato fino alla causa: `classify`

## 6.1 Il sintomo

```
DIVERGE  classify
    case 0  ref=0            emitted=-1
    case 1  ref=-2147483648  emitted=-1
    case 2  ref=2147483647   emitted=-1
    case 3  ref=0            emitted=-1
    case 4  ref=0            emitted=-1
    case 5  ref=-3           emitted=-1
```
Restituisce **sempre −1**, qualunque sia l'input. Non è un errore di calcolo:
è un ramo che vince sempre.

## 6.2 Il codice emesso è OTTIMO — il difetto non è dove sembra

`runs/base_0818/out/sample6_c/sub_1400014a0.c` ricostruisce lo `switch` con
tutti e 8 i case, aritmetica corretta, divisione con segno gestita bene:
```c
__int64 __fastcall classify(size_t a1, int a2, int a3) {
    if (a1 > 7) return classify_cold();
    switch (a1) {
        case 0: result = a3 + a2; return result;
        case 1: result = a2; result -= a3; return result;
        case 2: result = a3; result *= a2; return result;
        case 3: result = 0; if (a3 == 0) { return result; }
                __rdx_rax = result; a2 = __rdx_rax % a3;
                result = __rdx_rax / a3; /* signed */; return result;
        …
```
Il lavoro difficile (recupero switch da jump table) è **riuscito**.

## 6.3 La causa: larghezza del primo parametro

| | firma |
|---|---|
| **sorgente** (`src/sample6_constructs.c:13`) | `int32_t classify(int32_t op, int32_t a, int32_t b)` |
| **emesso** | `__int64 __fastcall classify(size_t a1, int a2, int a3)` |

Il primo parametro è tipizzato **`size_t`** (64 bit, senza segno) invece di
`int32_t`. **Gli altri due sono corretti.**

Meccanica del fallimento: il chiamante passa un `int32_t` in `ecx`, lasciando i
32 bit alti di `rcx` con spazzatura. Il codice emesso legge `rcx` a 64 bit →
`a1 > 7` è **sempre vero** → ramo `default` → `classify_cold()` → `-1`.
Il sorgente conferma: `default: return -1;`.

Causa probabile a monte: l'indicizzazione della jump table avviene in 64 bit e
l'inferenza ha dedotto `size_t` dal registro, invece di prendere la larghezza
dallo **scrutinio dello switch** (32 bit).

## 6.4 Perché questo caso vale come argomento generale

| metrica | vede il difetto? |
|---|---|
| `check.sh` (ricompilabilità) | **no** — compila perfettamente |
| `fidelity_arity` | **no** — 3 parametri, conteggio corretto |
| `callsite_consistency` (nuova) | **no** — le chiamate hanno 3 argomenti |
| `cross_build` | **no** — sbagliata allo stesso modo ovunque |
| **`behaviour`** | **SÌ** — è l'unica |

Un solo parametro largo 64 bit invece di 32 trasforma una funzione ricostruita
bene in una che restituisce sempre `-1`. È lo stesso argomento che CLAUDE.md
porta con `count_set_flags` (confidenza 92 «no signals» mentre legge 32 byte
oltre): **le metriche di forma sono strutturalmente cieche a questa classe**.

## 6.5 Bersaglio di correzione

Recupero della **larghezza dei parametri**, in particolare: quando un parametro
è lo scrutinio di uno `switch`, la larghezza va presa dal confronto/indice
originale, non dal registro a 64 bit usato per indicizzare la tabella.
Crate pertinente: `ParameterTypeInference` / `InferredSignature` di
`rustre-analysis-type` (355 elementi inutilizzati su 403).

## 6.6 Gli altri DIVERGE — firme diverse, cause diverse

- **`my_strlen`**: `ref=1 emitted=48`, `ref=11 emitted=72`, `ref=16 emitted=136`
  — restituisce valori non lineari rispetto alla lunghezza attesa.
- **`apply`**: `ref=7 emitted=-2147476636` — valore vicino a `0x8000….`, tipico
  di un indirizzo troncato a `int`. CLAUDE.md documenta già che `apply` emette
  `f(v2, a3, a3)` dove il sorgente chiama `f(a2, a3)`, passando un puntatore a
  funzione come primo argomento.
- **`accumulate` (rust)**: `ref=140699064605653 emitted=140699064605663` —
  **scarto di 10** su un valore che è chiaramente un puntatore, più «buffer
  contents differ after call».
- **`count_set_flags`**: `ref=3 emitted=2`, `ref=0 emitted=4` — il caso noto,
  legge 32 byte oltre ogni elemento.

Sono quattro cause distinte: larghezza parametro, calcolo del ritorno, ordine
degli argomenti, aritmetica dei puntatori. **Non esiste una correzione unica
per i DIVERGE**, vanno presi uno a uno — ed è il motivo per cui restano per
ultimi nella coda (§5.4).

---

# Round 7 — 2026-08-18 — Verità dal codice macchina: il `size_t` è inventato

## 7.1 Disassemblato di `classify` (`sample6_c.exe`, VA `0x1400014a0`)

```asm
0x1400014a0  cmp     $7, %ecx        ← confronto a 32 BIT, su ECX
0x1400014a3  ja      0x140002940     ← senza segno (unsigned above)
0x1400014a9  lea     0x2B50(%rip), %rax
0x1400014b0  mov     %ecx, %r9d      ← movimento a 32 bit
0x1400014b3  movslq  (%rax,%r9,4), %r9
0x1400014b7  add     %rax, %r9
0x1400014ba  jmp     *%r9
…
0x1400014c0  mov     %r8d, %eax
0x1400014c3  xor     %edx, %eax
0x1400014c5  ret                     ← coda del case 6
```

## 7.2 Conclusione: l'allargamento a 64 bit è un'INVENZIONE, non una lettura

Il confronto è `cmp $7, %ecx` — **32 bit**, non `%rcx`. Il codice macchina usa
esplicitamente il registro a 32 bit. Tipizzare il parametro `size_t` (64 bit)
non è fedeltà al binario: è un allargamento introdotto dal decompilatore.

**La correzione è netta e non richiede euristiche: la larghezza del parametro va
presa dal registro effettivamente usato** (`ecx` → 4 byte).

Nota semantica: `ja` è senza segno, quindi emettere `unsigned int` a 32 bit
riprodurrebbe *esattamente* il comportamento del sorgente — un `op` negativo
diventa un unsigned enorme, supera 7, e cade nel `default: return -1`. La firma
corretta è recuperabile dal solo codice macchina, senza conoscere il sorgente.

## 7.3 Secondo reperto: `INTERIOR_ADDRESS` è lo stesso difetto della jump table

`behavior.txt` riporta `sub_1400014C5: INTERIOR_ADDRESS (inside emitted
0x1400014a0)`. Dal disassemblato, `0x1400014c5` è il **`ret` dentro `classify`**,
subito dopo `xor %edx, %eax`: è la coda del `case 6`, cioè un **target della
jump table**.

Quindi i 3 `INTERIOR_ADDRESS` di §5.1 non sono una classe separata: sono
**target di jump table scambiati per punti d'ingresso di funzione**. Il
rilevatore di funzioni li promuove a `sub_…` e poi il link non li trova perché
stanno dentro un'altra funzione già emessa.

Conseguenza pratica: **una sola correzione** (non promuovere a funzione un
indirizzo che è target di una jump table già riconosciuta, e che cade dentro il
range di una funzione emessa) chiude i 3 `INTERIOR_ADDRESS`.

## 7.4 Aggiornamento della coda

Due bersagli nuovi, entrambi con causa dimostrata dal codice macchina:

| bersaglio | evidenza | correzione |
|---|---|---|
| larghezza parametro allargata 32→64 | `cmp $7, %ecx` contro `size_t a1` | prendere la larghezza dal registro usato |
| `INTERIOR_ADDRESS` (3) | `0x1400014c5` è il `ret` del case 6 | non promuovere a funzione i target di jump table interni |

Entrambi appartengono alla famiglia di `rustre-analysis-type` /
`rustre-analysis-fn`, crate con 355 e ~350 elementi inutilizzati.

---

# Round 8 — 2026-08-18 — Secondo DIVERGE sezionato: `my_strlen`, e il pattern che emerge

## 8.1 Sorgente contro emesso

**Sorgente** (`src/sample11_c_features.c:71`):
```c
size_t my_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;              /* pointer-walk loop, passo 1 */
    return (size_t)(p - s);
}
```

**Emesso** (`runs/base_0818/out/sample11_c/sub_140001550.c`):
```c
__int64 __fastcall my_strlen(char *a1) {
    __int64 *result;                  // ← TIPO DELL'ELEMENTO SBAGLIATO
    if (*a1 == 0) { result = 0; return (__int64)result; }
    result = (__int64 *)a1;
    do {
        ++result;                     // avanza di 8 byte, non di 1
    } while (*result != 0);           // legge 8 byte, non 1
    result = (__int64 *)((__int64)result - (__int64)a1);
    return (__int64)result;
}
```

## 8.2 Causa e verifica numerica

La variabile di scorrimento è tipizzata `__int64 *` invece di `char *`:
`++result` avanza di **8 byte** e `*result` legge 8 byte alla volta, quindi la
condizione diventa falsa solo quando trova **otto byte di zero consecutivi** —
ben oltre la fine della stringa.

Verifica sui numeri di `behavior.txt`:

| ref (atteso) | emitted | emitted / 8 |
|---|---|---|
| 1 | 48 | **6** |
| 11 | 72 | **9** |
| 16 | 136 | **17** |

**Tutti multipli esatti di 8.** L'ipotesi è confermata dai dati, non solo dalla
lettura del codice.

Da notare: il **parametro** `char *a1` è tipizzato correttamente, e anche il
primo `*a1 == 0` legge un byte solo. Sbaglia **unicamente il tipo dell'elemento
della variabile di ciclo**. Quindi non è un fallimento generale del recupero
tipi: è la propagazione del tipo puntatore dal parametro alla variabile di
scorrimento che non avviene.

Nota: CLAUDE.md elenca fra le feature «pointer-stride `do/while` → `for`» e
«strength-reduced pointer loop → counted `for (i…) base[i]`». La macchina per
gli stride esiste; qui è il **tipo dell'elemento** a essere sbagliato, il che
suggerisce che quella macchina lavori sul passo senza consultare il tipo del
puntatore di partenza.

## 8.3 IL PATTERN: i DIVERGE analizzati sono difetti di TIPO, non di flusso

| funzione | struttura ricostruita | difetto reale |
|---|---|---|
| `classify` | switch a 8 case **perfetto** | parametro allargato 32→64 bit (`size_t` invece di `int32`) |
| `my_strlen` | ciclo pointer-walk **corretto** | elemento del puntatore 8 byte invece di 1 |

In **entrambi** i casi il lavoro difficile (structuring, recupero switch,
riconoscimento del ciclo) è riuscito, e **il tipo tradisce il risultato**.

Conseguenza per la strategia: l'investimento con il miglior ritorno sui DIVERGE
non è lo structuring (che funziona) ma il **recupero dei tipi** — cioè
`ParameterTypeInference` / `InferredSignature` di `rustre-analysis-type`
(355 elementi inutilizzati su 403) e `MlilTypeRecovery` / `ConstraintGenerator`
di `rustre-il-mlil` (mai istanziati).

Questo rafforza e precisa la voce 9 della coda (§4.6): non «argomenti e firme»
genericamente, ma **larghezze e tipi di elemento**.

⚠ Campione: 2 DIVERGE su 11. Il pattern è forte ma **non ancora dimostrato per
tutti**; `apply` (ordine argomenti) e `accumulate` (aritmetica puntatori, scarto
di 10) potrebbero avere cause diverse. Da verificare prima di generalizzare.

---

# Round 9 — 2026-08-18 — Terzo DIVERGE: il pattern del Round 8 è FALSIFICATO, e ne emerge uno migliore

## 9.1 `apply` — sorgente contro emesso

**Sorgente** (`src/sample6_constructs.c:36`):
```c
static int32_t add_fn(int32_t x, int32_t y) { return x + y; }
static int32_t mul_fn(int32_t x, int32_t y) { return x * y; }
int32_t apply(int use_mul, int32_t x, int32_t y) {
    binop f = use_mul ? mul_fn : add_fn;
    return f(x, y);                    // DUE argomenti
}
```

**Emesso** (`runs/base_0818/out/sample6_c/sub_140001580.c`):
```c
__int64 __fastcall apply(int a1, int a2, int a3) {
    func_ptr = &add_fn;
    v2 = &mul_fn;
    if (a1 != 0) func_ptr = v2;                      // ← selezione CORRETTA
    return ((__int64 (*)())func_ptr)(v2, a3, a3);    // ← argomenti SBAGLIATI
}
```
Corretto sarebbe `(a2, a3)`. Emesso: primo argomento = puntatore a `mul_fn`,
e uno in più.

## 9.2 La prova dal codice macchina (VA `0x140001580`)

```asm
0x140001580  lea     -0x107(%rip), %rax   ; rax = add_fn
0x140001587  test    %ecx, %ecx           ; testa use_mul (a1)
0x140001589  mov     %edx, %ecx           ; ecx = x    ← arg0 preso QUI, da edx
0x14000158b  lea     -0x102(%rip), %rdx   ; rdx = mul_fn  ← edx CLOBBERATO
0x140001592  cmovne  %rdx, %rax           ; rax = use_mul ? mul_fn : add_fn
0x140001596  mov     %r8d, %edx           ; edx = y    ← arg1
0x140001599  jmp     *%rax                ; TAIL CALL
```

Argomenti corretti al momento del salto: `ecx = a2` (copiato da `edx` **prima**
della sovrascrittura) e `edx = a3`.

Il decompilatore ha risolto il feeder di `ecx` fino a `edx`, e ha poi sostituito
**l'ultima definizione di `edx`** (il `lea` di `mul_fn` a `0x14000158b`) invece
di quella **viva al momento della `mov`** (`0x140001589`).

## 9.3 Causa: assenza di SSA reale

È esattamente il difetto che la forma SSA impedisce: senza versioning, `edx` è
una variabile sola e la sostituzione pesca la definizione sbagliata.

Su path A gira `ssa_split::split_versions` (`lib.rs:19368`), un rinominatore
**testuale** di live-range su blocchi CFS: **niente PHI, niente dominanza**
(§1.3). `MlilFunction::into_ssa()` — che ha frontiera di dominanza iterata e
piazzamento PHI — è **spenta** dietro `RUSTRE_MLIL_SSA` (`lib.rs:28502`).

## 9.4 Il pattern del Round 8 è falsificato — e sostituito da uno più forte

Il Round 8 ipotizzava «i DIVERGE sono tutti difetti di tipo». **Falso**: `apply`
è un difetto di versione/liveness, non di tipo. Ipotesi verificata e scartata.

Quello che regge, su 3 casi su 3:

| funzione | causa | componente di catena non cablato |
|---|---|---|
| `classify` | larghezza parametro 32→64 bit | `ParameterTypeInference` / `InferredSignature` — 355 inutilizzati su 403 |
| `my_strlen` | tipo elemento puntatore 8 byte invece di 1 | recupero tipi / `MlilTypeRecovery` — mai istanziato |
| `apply` | versione sbagliata del registro alla tail call | **SSA MLIL** — esiste, completa, **spenta** |

**Non sono capacità mancanti: sono componenti della catena non cablati.** È la
tesi dell'utente (§obiettivo), qui confermata **sulla metrica comportamentale**
invece che per ispezione del codice — cioè dal lato che conta.

In tutti e tre i casi la parte difficile (switch recovery, riconoscimento del
ciclo pointer-walk, selezione del puntatore a funzione con `cmovne`) è
**riuscita**, e il pezzo mancante l'ha annullata.

## 9.5 Effetto sulla coda

Sale la voce «SSA MLIL accesa» (§4.6 voce 8): non serve solo a togliere i 2151
`flag_zf` di path B — **corregge una classe di DIVERGE su path A**. È un
esperimento a gate (`RUSTRE_MLIL_SSA=1`), quindi a costo di codice quasi nullo,
e ora ha un bersaglio comportamentale dimostrato.

⚠ Da verificare misurando: `into_ssa()` è spenta di default e il commento a
`lib.rs:28473` dice che il suo unico chiamante «BUTTA la forma SSA e restituisce
una lista di stringhe». Accendere il gate potrebbe non bastare: va controllato
che il risultato arrivi davvero all'emissione.

---

# Round 10 — 2026-08-18 — Quarto DIVERGE: `accumulate` (rust) — diagnosi PARZIALE

## 10.1 Sorgente

`src/sample3_struct_loop.rs:13`:
```rust
pub extern "C" fn accumulate(pts: *mut Point, n: i32) -> i64 {
    let mut total: i64 = 0;
    let mut i = 0i32;
    while i < n {
        unsafe {
            let p = &mut *pts.offset(i as isize);
            p.sum = p.x + p.y;
            total += p.sum;
        }
        i += 1;
    }
```
`Point` = `{ x: i64, y: i64, sum: i64 }` → 24 byte (confermato dal `main`
emesso, che scrive 1,2,0 / 3,4,0 / 5,6,0 a passo 24).

## 10.2 Emesso (`runs/base_0818/out/sample3_rust/sub_1400010a0.c`)

```c
__int64 __fastcall accumulate(__int64 *a1, int a2) {   // ← NON Point*
    if (a2 <= 0) { result = 0; return result; }
    if (a2 != 1) {
        v5 = a2; v6 = v5; v6 &= 0x7FFFFFFE;   // ← arrotonda a PARI: unroll ×2
        dst = a1 + 5;
        do {
            v8 = *(dst - 4);          // y0
            v4 = *(dst - 1);          // y1
            v8 += *(dst - 5);         // + x0
            *(dst - 3) = v8;          // sum0 = x0 + y0   ✓
            v8 += result;
            v4 += *(dst - 2);         // + x1
```

Il compilatore ha **srotolato e vettorizzato** il ciclo (due `Point` per
iterazione, con `&= 0x7FFFFFFE` per la parte pari e presumibilmente una coda per
`n` dispari).

## 10.3 Cosa è verificato e cosa NO

**Verificato:** con `dst = a1 + 5`, gli indici `-5`→`x0`, `-4`→`y0`,
`-3`→`sum0`, `-2`→`x1`, `-1`→`y1` sono **corretti**, e la prima iterazione
calcola `sum0 = x0 + y0` giusto. Gli offset non sono il difetto.

**NON verificato:** la gestione della **coda** del ciclo srotolato (ramo per `n`
dispari) e l'accumulo di `total`. Lo scarto di **10** fra `ref` e `emitted`
(`140699064605653` vs `140699064605663`) e il «buffer contents differ after
call» sono coerenti con un elemento processato in più o in meno, ma **non l'ho
dimostrato**.

**Difetto certo ma non sufficiente a spiegare il DIVERGE:** il tipo è
`__int64 *a1` invece di `Point *` — la struttura non è stata recuperata, e il
ciclo è emesso come aritmetica di puntatori grezza su offset costanti.

## 10.4 Stato di questo caso

`accumulate` è dichiarato **diagnosi parziale** e **non viene contato** fra le
cause dimostrate del Round 9. Serve un giro dedicato sulla coda del ciclo
srotolato. Annotato qui per non ripartire da zero.

## 10.5 Riepilogo DIVERGE analizzati finora

| funzione | stato | causa | componente non cablato |
|---|---|---|---|
| `classify` | **dimostrata** | larghezza parametro 32→64 | `ParameterTypeInference` |
| `my_strlen` | **dimostrata** | elemento puntatore 8 byte invece di 1 | recupero tipi / `MlilTypeRecovery` |
| `apply` | **dimostrata** | versione sbagliata del registro (tail call) | SSA MLIL (spenta) |
| `accumulate` | **parziale** | struct non recuperata + coda unroll da verificare | `StructBuilder` / recupero struct |
| `count_set_flags` | nota da CLAUDE.md | legge 32 byte oltre ogni elemento | non riverificata in questa sessione |

---

# Round 11 — 2026-08-18 — `count_set_flags`: il doppio scalamento, e la classe più redditizia

## 11.1 Verifica indipendente di un'affermazione di CLAUDE.md

CLAUDE.md afferma che `count_set_flags` «legge 32 byte oltre ogni elemento».
Verificata invece di assunta (le affermazioni di quel file si sono già rivelate
stale oggi, §1.3 sui simboli dati di path A). **L'affermazione REGGE**, e ora c'è
il meccanismo preciso.

## 11.2 Sorgente contro emesso

**Sorgente** (`src/sample6_constructs.c:45`):
```c
uint32_t count_set_flags(const uint32_t *flags, size_t n) {
    uint32_t total = 0; size_t i = 0;
    do {
        uint32_t v = flags[i];        // elemento 4 byte, offset i*4
        if (v & FLAG_A) total++;
        if (v & FLAG_B) total++;
        if (v & FLAG_C) total++;
        i++;
    } while (i < n);
```

**Emesso** (`runs/base_0818/out/sample6_c/sub_1400015a0.c`):
```c
int __fastcall count_set_flags(__int64 *a1, __int64 a2) {   // ← __int64*, non uint32_t*
    do {
        v3 = *(a1 + count*4);        // ← DOPPIO SCALAMENTO
        v5 = v3; v5 &= 1; result += v5;
        v2 = v3; v2 &= 2; result += (v2 != 0);
        v3 &= 4;          result += (v3 != 0);
        ++count;
    } while (count < a2);
```

## 11.3 Meccanismo: il fattore di scala applicato DUE VOLTE

In C l'aritmetica dei puntatori moltiplica per la dimensione dell'elemento.
Con `a1` di tipo `__int64 *` (8 byte):

```
a1 + count*4   →   avanza di  count × 4 × 8 = count × 32 byte
```

Il decompilatore ha letto **correttamente la scala 4** dal codice macchina
(`mov eax, [rcx+rdx*4]`) e l'ha emessa esplicitamente, ma ha sbagliato il **tipo
della base**: C poi riapplica il fattore 8. Da cui i 32 byte per elemento invece
di 4.

**Secondo difetto sovrapposto:** `*(a1 + …)` su `__int64 *` **legge 8 byte**
dove il sorgente ne legge 4.

La logica dei flag (`&1`, `&2`, `&4` e i tre incrementi condizionali) è invece
ricostruita **correttamente**.

Correzione: tipizzare `a1` come `uint32_t *` ed emettere `a1[count]`. In
alternativa `*(uint32_t *)((char *)a1 + count*4)`, ma la prima è quella giusta.

## 11.4 La classe più redditizia sui DIVERGE

Bilancio delle cause dimostrate (4 su 5 analizzate; `accumulate` resta parziale):

| funzione | causa | famiglia |
|---|---|---|
| `classify` | larghezza parametro 32→64 bit | **tipo** (larghezza scalare) |
| `my_strlen` | elemento puntatore 8 invece di 1 | **tipo** (elemento puntato) |
| `count_set_flags` | elemento puntatore 8 invece di 4 → doppio scalamento ×32 | **tipo** (elemento puntato) |
| `apply` | versione sbagliata del registro alla tail call | **SSA assente** |

**Due delle quattro sono lo stesso identico difetto**: il tipo dell'elemento
puntato. E in entrambi i casi la struttura del ciclo è ricostruita bene, il che
isola il problema nel recupero tipi e non nello structuring.

**Il tipo dell'elemento puntato è quindi la singola classe più redditizia sui
DIVERGE.** Bersaglio: propagazione del tipo puntatore dal parametro/accesso alla
variabile di scorrimento — `MlilTypeRecovery` / `ConstraintGenerator` di
`rustre-il-mlil` (mai istanziati) e `PointerTypeChain` / `ArrayAccessPattern` di
`rustre-analysis-type` (mai usati).

Indizio prezioso per la correzione: in `count_set_flags` la **scala corretta (4)
è già stata recuperata** ed è nel codice emesso. L'informazione per dedurre
`uint32_t *` c'è già — manca di essere usata per tipizzare la base invece che
solo per indicizzare.

---

# Round 12 — 2026-08-18 — CORREZIONE al Round 9: la SSA alimenta SOLO path B

## 12.1 Cosa avevo concluso (§9.5) e perché è SBAGLIATO

Nel Round 9 avevo scritto che accendere `RUSTRE_MLIL_SSA` «corregge una classe
di DIVERGE su path A». **Falso.** Letto il commento in-source a `lib.rs:28470`:

> «`MlilFunction::into_ssa()` esiste e funziona ma il suo risultato non arrivava
> mai a valle: l'unico chiamante (`mlil_ssa_split::reuse_hints`) BUTTA la forma
> SSA e restituisce una lista di stringhe. **Qui la forma SSA ALIMENTA davvero
> il path B**: `lift_structured(&mlil_func)` qui sotto riceve MLIL in vera forma
> SSA (versioni distinte + PHI ai punti di join).»

**La SSA alimenta esclusivamente path B**, che è spento di default. Path A non
vede mai il MLIL: lavora sul disassemblato testuale (§1.3).

Quindi `RUSTRE_MLIL_SSA=1` da solo **non tocca** il difetto di `apply` misurato
su path A.

## 12.2 Ma la conseguenza RAFFORZA la direttiva «path B»

Il difetto di `apply` (§9.2-9.3) nasce da `ssa_split::split_versions`, il
rinominatore **testuale** di path A — senza PHI e senza dominanza. Non è
correggibile con la SSA vera **senza passare a path B**.

Conclusione corretta: **path B + SSA è l'architettura giusta, e path A non è
riparabile allo stesso modo.** La direttiva dell'utente («path B unico») ha qui
una giustificazione tecnica indipendente, misurata sul comportamento.

## 12.3 Due vincoli tecnici da rispettare quando si toccherà quel codice

Dal commento a `lib.rs:28470-28494`, entrambi già misurati dal precedente autore:

1. **Posizione del blocco SSA**: sta DOPO il type-recovery e DOPO la VSA *di
   proposito*. Quei due scrivono in `ctx.variables`/annotazioni **condivise con
   path A**, indicizzate per `format!("{}#{}", var.name, var.version)`.
   Rinominare le versioni prima cambierebbe quelle chiavi e **sposterebbe i tipi
   di path A**. → Non spostare il blocco più in alto.
2. **`RUSTRE_MLIL_OPT` è annidato dentro `RUSTRE_MLIL_SSA`** e non è attivabile
   da solo: `ConstantProp` (`mlil_optimizer.rs`) costruisce una mappa
   `SsaVar -> costante` **senza controllo di dominanza**; su MLIL non-SSA (tutte
   le variabili a versione 0) propagherebbe la costante di un blocco sugli usi
   di un altro, producendo **C sbagliato**. → Mai accendere l'ottimizzatore
   senza la SSA.

## 12.4 Effetto sulla coda

- La voce «SSA MLIL accesa» **torna a valere solo per path B** (i 2151
  `flag_zf`), non per i DIVERGE di path A. Ridimensionata rispetto al Round 9.
- Il difetto `apply` su path A resta aperto e ha due sole vie: correggere il
  rinominatore testuale, oppure **completare il passaggio a path B**.
- Nota operativa: `RUSTRE_MLIL_SSA=1` da solo non produce alcun effetto
  osservabile finché path B è spento → l'esperimento va fatto **insieme** a
  `RUSTRE_HLIL=1`, non da solo.

## 12.5 Osservazione d'ambiente

Alle 11:24 risultavano **8-10 processi python** attivi (da 3 MB a 206 MB di
memoria) invece di uno. Nessun nuovo snapshot in `runs/`, quindi non è un altro
agente che misura sullo stesso albero: sono worker paralleli. Il mio snapshot
`base_0818` resta isolato per costruzione (ogni run scrive nella propria
directory), quindi la **correttezza è preservata**; l'effetto è solo contesa di
CPU. Annotato perché `runs/` è condiviso fra agenti e questa verifica va rifatta
ogni volta che i tempi si allungano.

---

# Round 13 — 2026-08-18 — Mossa 0: patch pronta all'applicazione

Registrata qui per intero perché sopravviva alla sessione ed sia applicabile
anche da un altro agente.

## 13.1 `tests/decompiler_corpus/behavior.py` — nuovo argomento `--json-out`

**Punto 1** — dopo `ap.add_argument("--json", action="store_true")` (riga 506):

```python
    ap.add_argument("--json-out", metavar="PATH",
                    help="also write the JSON payload to PATH while stdout "
                         "stays the text report. One run, both outputs: "
                         "measure.sh used to invoke this script TWICE (once "
                         "per format) and each run compiles, links and executes "
                         "63 functions against 2000-3300 objects per bucket -- "
                         "~30 minutes thrown away per measurement.")
```

**Punto 2** — sostituire il blocco alle righe 567-579:

```python
    total = sum(tally.values())
    agree = tally.get("AGREE", 0)
    # Per-function status travels with the counts. Counts alone hide a swap:
    # one function regressing AGREE->DIVERGE while another improves leaves the
    # totals identical and the output quietly worse.
    per_fn = {f"{b}:{n}": r["status"]
              for b, fns in results.items()
              for n, r in fns.items() if n != "_bucket"}
    payload = json.dumps({"total": total, "agree": agree, "tally": tally,
                          "pct": round(100.0 * agree / total, 2) if total else 0.0,
                          "functions": per_fn})
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    if a.json:
        print(payload)
        return 0
```

(`argparse` mappa `--json-out` su `a.json_out`. Il ramo `--json` resta intatto
per compatibilità con eventuali chiamanti esterni.)

## 13.2 `tests/decompiler_corpus/measure.sh` — righe 157-158

Da:
```bash
python "$CORPUS/behavior.py" "$DEST/out" > "$DEST/behavior.txt" 2>&1
python "$CORPUS/behavior.py" "$DEST/out" --json > "$DEST/behavior.json" 2>/dev/null
```
A:
```bash
python "$CORPUS/behavior.py" "$DEST/out" --json-out "$DEST/behavior.json" \
       > "$DEST/behavior.txt" 2>&1
```

## 13.3 Verifica attesa

- `behavior.txt` e `behavior.json` devono avere lo **stesso contenuto** di
  `runs/base_0818` (che li ha prodotti con due esecuzioni separate): è il
  controllo che la patch non cambia i risultati, solo il costo.
- Tempo di `behavior.py` atteso: **una sola** esecuzione da ~30 min invece di
  due → misura completa da ~62 a ~32 minuti. **Da misurare, non da assumere.**
- ⚠ `behavior.py` è nell'impronta degli harness (`measure.sh:97`): il primo
  `--compare` successivo dirà `changed (harness differs)`. Previsto.

## 13.4 Perché NON è ancora applicata

`measure.sh` era ancora in esecuzione: modificare uno script bash mentre gira è
pericoloso (bash rilegge il file durante l'esecuzione), e vale anche per
`behavior.py`, che quel `measure.sh` sta invocando in questo momento.

---

# Round 14 — 2026-08-18 — Mossa 2 (`JUMPOUT` → tail call): patch pronta

Requisito esplicito dell'utente: **0 `goto` e 0 `JUMPOUT`**. I `goto` sono già
a 0 (§1.5). Restano 18 `JUMPOUT`, tutti della stessa forma.

## 14.1 Testo attuale — `lib.rs:17937-17946`

```rust
        if let Some(op) = text.strip_prefix("JUMPOUT(").and_then(|t| t.strip_suffix(");"))
            && !op.is_empty()
            && op.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !op.starts_with(|c: char| c.is_ascii_digit())
            && !op.starts_with("off_")
            && !op.starts_with("loc_")
        {
            *s = CfsStatement::Return(Some(format!("{op}()")));
            continue;
        }
```
La guardia `op.chars().all(alphanumeric || '_')` accetta **solo identificatori
semplici** ed esclude gli operandi di memoria — il commento sopra lo dichiara.

## 14.2 Testo proposto

```rust
        if let Some(op) = text.strip_prefix("JUMPOUT(").and_then(|t| t.strip_suffix(");"))
            && !op.is_empty()
            && !op.starts_with(|c: char| c.is_ascii_digit())
            && !op.starts_with("off_")
            && !op.starts_with("loc_")
        {
            // Un operando di MEMORIA — `*v6`, `ptr->field_18`,
            // `*(result + 32)` — e' una tail call esattamente quanto un
            // registro nudo: un salto indiretto in posizione di coda trasferisce
            // il controllo e il ritorno del chiamato diventa il nostro, che in C
            // e' precisamente `return f();`.
            //
            // MISURATO su runs/base_0818: tutti i 18 JUMPOUT residui hanno
            // questa forma — `ptr->field_18` x8, `result->field_48` x2,
            // `ptr->field_38` x2, `ptr->field_30` x2, `*v6` x2,
            // `*(result + 32)` x2 — e `JUMPOUT` NON e' definito in ida_defs.h
            // (35 righe, 0 occorrenze): ognuno e' quindi una dichiarazione
            // implicita che passa `-fsyntax-only -w` e ROMPE IL LINK.
            //
            // Parentesizzato perche' `cast_indirect_call_targets` lo riconosca:
            // quel pass gia' gestisce e testa `(ptr->field_30)();` e `(*v2)();`
            // (lib.rs:8632), incluso il caso dentro `return` (lib.rs:39522).
            let plain = op.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            let mem = op.starts_with('*') || op.contains("->");
            if plain || mem {
                let callee = if plain { op.to_string() } else { format!("({op})") };
                *s = CfsStatement::Return(Some(format!("{callee}()")));
                continue;
            }
        }
```
Se non e' ne' `plain` ne' `mem`, si cade nel ramo `goto loc_` sottostante come
oggi: comportamento invariato per tutto il resto.

## 14.3 Un effetto collaterale che è una CORREZIONE, non un rischio

In `sub_140007030.c` il `JUMPOUT` e' seguito da altre istruzioni nello stesso
blocco (`v3 = 0; *a3 = v3; result = 0xFFFFFFFF; return result;`). Convertirlo in
`return` le rende irraggiungibili.

**È corretto**: un `JUMPOUT` e' un trasferimento di controllo incondizionato,
quindi quel codice era gia' morto nel binario. Oggi però `JUMPOUT` e' una
funzione inesistente, quindi nel C ricompilato quelle righe **verrebbero
eseguite davvero** — cioe' il comportamento attuale e' sbagliato e la
conversione lo raddrizza.

## 14.4 Verifica attesa

- `JUMPOUT` nel corpus: **18 → 0**;
- `goto`: deve restare **0**;
- recompilabilita': non deve scendere (il pass di cast e' gia' testato);
- `behaviour`: possibile miglioramento sui LINK_FAIL che dipendevano dalla
  dichiarazione implicita di `JUMPOUT`;
- ⚠ da controllare che non compaiano nuovi `implicit declaration` — la
  conversione toglie `JUMPOUT` ma introduce una chiamata attraverso puntatore,
  che il pass di cast deve coprire in **tutti** e 18 i casi, non in 16.

## 14.5 Nota

Resta separato il caso `v6 = &sub_140052130; return JUMPOUT(*v6);`
(`sub_140024590.c`), dove il bersaglio e' **staticamente noto**: la conversione
lo rende `return (*v6)();`, corretto ma ancora indiretto. Renderlo
`return sub_140052130();` richiede la propagazione di costanti, cioe'
`ConstantPropagationPass` di `il-passes` — mai eseguito (§1.3).

---

# Round 15 — 2026-08-18 — CORREZIONE al Round 1 §1.6a: la causa dei 4 fantasmi NON è la regola D9

## 15.1 Cosa avevo scritto (§1.6a) e perché è SBAGLIATO

Avevo scritto che i 4 parametri fantasma di `_pei386_runtime_relocator`
nascono dalla regola D9: il call site `__mingw_GetSectionCount(a1,a2,a3,a4)`
farebbe dedurre rcx/rdx/r8/r9 vivi in ingresso, promuovendoli a parametri del
chiamante. **Falsificato da tre misure indipendenti.**

## 15.2 Le tre misure

**(a) La sonda D9 non scatta mai.** Eseguito
`RUSTRE_DBG_PARAMREG=1 dump_decompile.exe sample1.exe <scratch>`: 43 file
emessi, `_pei386_runtime_relocator` esce ancora con 4 parametri, e la sonda
stampa **zero** righe `[PARAMREG]`. La regola D9 non è mai entrata in funzione
su questo binario. (La sonda è quella descritta a `lib.rs:2478`, aggiunta dal
precedente autore proprio per rispondere a questa domanda.)

**(b) L'arity vera di `__mingw_GetSectionCount` è 0, non 4.** Disassemblata a
`0x1400023f0`: la funzione è lunga **55 byte** (`0x1400023f0..=0x140002426`) e
**non legge alcun registro argomento** — `xor %ecx, %ecx` azzera rcx, `rax`
viene da `mov 0x1FA9(%rip), %rax`. Nessuna `call` nel corpo, quindi D9 non
potrebbe scattare nemmeno per lei. La definizione emessa
(`__int64 __fastcall __mingw_GetSectionCount()`, 0 parametri) è **corretta**.

Cade anche la mia ipotesi secondaria di over-scan: `CALLEE_SCAN_BYTES = 4096`
farebbe temere che la scansione prosegua nelle funzioni successive, ma
`disasm_dump` riporta `fn instr range: 0x1400023f0..=0x140002426`, cioè il
confine è individuato correttamente.

**(c) Il chiamante non legge registri argomento all'ingresso.** Disassemblato
`_pei386_runtime_relocator` a `0x140001a00`: il prologo salva 8 registri
callee-saved (`push %rbp/%r15/%r14/%r13/%r12/%rdi/%rsi/%rbx`), alloca
`sub $0x48,%rsp`, e legge `mov 0x5685(%rip), %esi` — **memoria, non argomenti**.
Zero parametri, coerente con il prototipo pubblicato (`want 0`).

## 15.3 Stato: causa APERTA

I 4 parametri fantasma sono reali e misurati (§1.6a resta valido come
*sintomo*), ma la **causa è ignota**. Escluse:
- la regola D9 (sonda muta);
- un'arity sbagliata del chiamato (è 0 e corretta);
- l'over-scan del corpo del chiamato (confine corretto);
- una lettura di registri argomento nel prologo del chiamante (non c'è).

Restano da esaminare: le altre regole dentro `win64_param_regs_live_in`
(`lib.rs:2450`, in particolare il ramo «anything reading the reg before write is
a param signal») applicate a punti PIÙ AVANTI nel corpo, e la possibilità che il
produttore dei parametri sia un pass diverso da `win64_param_regs_live_in`.

Prossimo passo: disassemblare `_pei386_runtime_relocator` **per intero** e
individuare il primo punto in cui rcx/rdx/r8/r9 vengono letti prima di essere
scritti; e verificare se `infer_call_arguments` al call site produca la lettura
che poi il rilevatore di parametri interpreta come «vivo in ingresso»
(causalità inversa rispetto a quella che avevo assunto).

## 15.4 Nota di metodo

È la seconda conclusione mia falsificata oggi (dopo §12.1 sulla SSA) e la terza
ipotesi caduta (dopo il pattern «tutti difetti di tipo» del §9.4). In tutti e
tre i casi la spiegazione era **plausibile e sbagliata**, e a smontarla è stata
una misura diretta — sonda, disassemblato, esecuzione — non un ragionamento più
attento. Conferma operativa di [[feedback-misurare-non-dedurre]]: il primo fix
plausibile va trattato come sospetto finché una misura non lo conferma.

---

# Round 16 — 2026-08-18 — Meccanismo CONFERMATO per i fantasmi: destinazione AT&T letta al contrario

## 16.1 Il punto nel binario

Disassemblato `_pei386_runtime_relocator` (`0x140001a00`), i registri argomento
compaiono in **sole tre righe**, tutte su `edx`:

```asm
0x140001a93  mov  (%rbx), %edx      ← AT&T: la DESTINAZIONE è il SECONDO operando
0x140001a95  test %edx, %edx
0x140001aa8  mov  8(%rbx), %edx
0x140001aab  cmp  $1, %edx
```
(più due `call`, a `0x1400023F0` e `0x140002640`.)

In AT&T `mov (%rbx), %edx` significa **edx = [rbx]**: edx è SCRITTO, non letto.

## 16.2 Il difetto è già ammesso nel sorgente

Commento dentro `win64_param_regs_live_in` (`lib.rs:2450`):

> «the read/write classification reads the first operand as the destination and
> so misclassifies AT&T memory-source loads (`mov 0x1234(%rip), %rcx`) as "not a
> write"»

E in `RawMnemonicView::writes_register` (`pass_pipeline.rs`):
```rust
if let Some((dst, _)) = self.operands.split_once(',') {   // ← primo operando = dst
```

Con operandi AT&T (`src, dst`) la destinazione è il **secondo**. Quindi
`mov (%rbx), %edx` viene classificato «edx non scritto»; edx è però menzionato,
e la regola «anything reading the reg before write is a param signal» lo
promuove a **parametro**.

**Questo è un meccanismo confermato, capace di generare parametri fantasma**, ed
è indipendente dalla regola D9 (che il Round 15 ha escluso con la sonda).

## 16.3 Contabilità NON ancora chiusa — dichiarato apertamente

Il meccanismo spiega un fantasma su `edx` (= `a2`). Ma la firma emessa ha
**quattro** parametri (`a1..a4`), e nell'intervallo disassemblato non compaiono
`rcx`/`r8`/`r9`. La contabilità **non torna**.

Filone aperto trovato nello stesso disassemblato: `disasm_dump` riporta
`fn instr range: 0x140001a00..=0x140001ac8` (200 byte, 56 istruzioni), ma
l'ultima istruzione è `jb 0x140001B44` — **un salto oltre il confine rilevato**.
La funzione continua e il rilevamento dei confini si è fermato presto. Il corpo
oltre `0x140001ac8` non è nel disassemblato esaminato, e potrebbe contenere gli
altri riferimenti a `rcx`/`r8`/`r9`.

⚠ Nota: il confine usato da `disasm_dump` potrebbe non essere lo stesso usato
dal decompilatore in emissione — il corpo emesso di `sub_140001a00.c` è molto
più esteso di 56 istruzioni. **Da verificare** prima di trarre conclusioni: due
rilevatori di confine diversi sarebbero a loro volta un difetto (e imparentato
con la classe `INTERIOR_ADDRESS` del §7.3).

## 16.4 Stato

- **Meccanismo confermato** (AT&T dst al contrario), documentato nel sorgente
  stesso, sufficiente a produrre fantasmi: **sì**.
- **Prova che spieghi tutti e 4 i parametri di questa funzione**: **no**.
- Prossimo passo: disassemblare oltre `0x140001ac8` e confrontare il confine di
  funzione usato in emissione con quello di `disasm_dump`.

Non viene proposta alcuna patch finché la contabilità non torna: una correzione
al classificatore AT&T è plausibile e forse giusta, ma il Round 15 ha già
mostrato oggi che «plausibile» non basta.

---

# Round 17 — 2026-08-18 — CAUSA RADICE DIMOSTRATA: destinazione AT&T letta come sorgente

## 17.1 La contabilità torna: tutti e quattro i registri

Il Round 16 aveva trovato `edx` ma mancavano `rcx`, `r8`, `r9`, e il
disassemblatore si fermava a `0x140001ac8` con un `jb 0x140001B44` che usciva
dal confine rilevato. Disassemblato **oltre** quel confine:

```asm
0x140001b44  mov  (%rbx), %r8d      ← r8d è la DESTINAZIONE (AT&T: 2° operando)
0x140001b47  mov  8(%rbx), %ecx     ← ecx è la DESTINAZIONE
0x140001b54  mov  (%r8), %r9        ← r9  è la DESTINAZIONE
```

Più quello già trovato:
```asm
0x140001a93  mov  (%rbx), %edx      ← edx è la DESTINAZIONE
```

**Quattro caricamenti da memoria, quattro registri argomento, quattro parametri
fantasma**: `rcx`→`a1`, `rdx`→`a2`, `r8`→`a3`, `r9`→`a4`. La contabilità di
§16.3 è **chiusa**.

## 17.2 Causa radice

`RawMnemonicView::writes_register` (`pass_pipeline.rs`):
```rust
if let Some((dst, _)) = self.operands.split_once(',') {   // ← primo operando = dst
```
prende il **primo** operando come destinazione. Il disassemblatore di questo
repo emette **AT&T** (`%rbx`, `mov src, dst`), dove la destinazione è il
**secondo**.

Conseguenza: ogni `mov [mem], reg` viene classificato «il registro NON è
scritto». Il registro è però menzionato, quindi la regola «anything reading the
reg before write is a param signal» lo promuove a **parametro**.

**Nessun coinvolgimento della regola D9** (esclusa dalla sonda muta, §15.2a),
**nessuna arity sbagliata del chiamato** (è 0 e corretta, §15.2b): è un **errore
di parsing degli operandi**.

Il difetto era già noto e documentato in-source (§16.2), ma la conseguenza era
stata aggirata in UN punto specifico (gating della regola D9 su `touched`
anziché su `written`) invece di correggere la causa.

## 17.3 Portata attesa

`arity` misura **6 OVER** (§1.5). Questa causa ne spiega almeno 4 in una sola
funzione, ed è **strutturale**: colpisce ogni funzione che carichi da memoria in
un registro argomento prima di usarlo — un pattern comunissimo. È quindi
plausibile che spieghi anche parte dei 9756 OVER di `callsite_consistency`.

⚠ «Plausibile» non è «misurato»: la portata va quantificata sul corpus dopo la
correzione, non prima.

## 17.4 Direzione della correzione (patch NON ancora scritta)

Il classificatore deve rispettare l'ordine AT&T: **la destinazione è l'ultimo
operando**, non il primo.

⚠ Prima di scrivere: verificare se esistano percorsi in sintassi **Intel** nello
stesso codice (il commento a `lib.rs:2450` cita entrambe le sintassi). Se il
campo `operands` può essere in entrambe, la correzione deve distinguerle — per
esempio dal prefisso `%` degli operandi AT&T — e non invertire ciecamente.

Rischio: il classificatore lettura/scrittura è usato da più passate; invertire
la destinazione cambia il comportamento di tutte. Va misurato con
`measure.sh --compare base_0818` guardando **arity OVER/UNDER**,
`callsite_consistency` e **behaviour** insieme: correggere le scritture potrebbe
far SPARIRE parametri veri altrove (UNDER), non solo i fantasmi.

## 17.5 Nota di metodo

Tre ipotesi cadute (§9.4, §12.1, §15.1) e poi la causa trovata **allargando il
disassemblato oltre il confine che lo strumento dichiarava**. Il confine
sbagliato di `disasm_dump` (§16.3) aveva nascosto tre quarti dell'evidenza: se
mi fossi fermato al range riportato dallo strumento, avrei concluso che il
meccanismo spiegava un solo parametro su quattro e l'avrei scartato.

---

# Round 18 — 2026-08-18 — Progetto della correzione: è una tassonomia, non un'inversione

## 18.1 Prerequisito verificato: la sintassi è SEMPRE AT&T

`rustre-arch-x86/src/lib.rs:179` usa **`GasFormatter`** (sintassi GNU AS =
AT&T). Nel crate **non esiste** alcun `IntelFormatter`/`NasmFormatter`/
`MasmFormatter`. Quindi `ins.operands` è sempre nella forma `src, dst`, e il
dubbio sollevato in §17.4 è chiuso: **non serve distinguere due sintassi**.

## 18.2 Ma «invertire e basta» sarebbe SBAGLIATO

Prendere ciecamente l'ultimo operando come destinazione rompe due classi:

| istruzione (AT&T) | ultimo operando | scrive il registro? |
|---|---|---|
| `mov (%rbx), %edx` | `%edx` | **sì** — scrittura pura |
| `lea 0x40(%rsp), %rbp` | `%rbp` | **sì** — scrittura pura |
| `movslq (%rax,%r9,4), %r9` | `%r9` | **sì** — scrittura pura |
| `cmp $7, %ecx` | `%ecx` | **NO** — scrive solo i flag |
| `test %edx, %edx` | `%edx` | **NO** — solo flag |
| `add %rdx, %rax` | `%rax` | **sì, ma lo LEGGE anche** |
| `push %rax` | `%rax` | **NO** — legge il registro, scrive memoria |

Con l'inversione cieca: `cmp`/`test` marcherebbero il registro come scritto e
farebbero **sparire parametri veri** (OVER → UNDER); `add`/`sub` perderebbero il
segnale di lettura sulla destinazione.

## 18.3 Tassonomia richiesta

1. **Scrittura pura sull'ultimo operando** (non lo legge):
   `mov`, `movl/movq/movb/movw`, `lea`, `movzx`/`movzbl`/`movzwl`,
   `movsx`/`movsbl`/`movswl`/`movslq`, `movabs`, `set<cc>`.
2. **Lettura + scrittura sull'ultimo operando**:
   `add`, `sub`, `and`, `or`, `xor` (operandi DIVERSI), `imul`, `adc`, `sbb`,
   `shl`, `shr`, `sar`, `rol`, `ror`, `neg`, `not`, `inc`, `dec`.
3. **Nessuna scrittura di registro** (solo flag o memoria):
   `cmp`, `test`, `push`, `jmp`, `j<cc>`, `call`, `ret`, `nop`.
4. **Caso già trattato**: `xor %r, %r` / `sub %r, %r` con lo **stesso** registro
   è azzeramento — scrittura pura, nessuna lettura. Il commento a `lib.rs:2450`
   documenta che questo caso era già stato corretto a mano perché
   `_GetPEImageBase` (prototipo `void`) apriva con `xor %edx, %edx` e usciva con
   due parametri.

## 18.4 Perché la correzione è più rischiosa delle altre due

`writes_register`/`reads_register` (`pass_pipeline.rs`, `RawMnemonicView`) sono
usati da **più passate**, non solo dal rilevatore di parametri. Cambiarne la
semantica cambia il comportamento di tutte insieme.

Criteri di misura obbligatori dopo la modifica, tutti contro `base_0818`:
- `arity`: **OVER deve scendere**, e **UNDER non deve salire** (se sale, la
  tassonomia sta cancellando parametri veri);
- `callsite_consistency`: OVER deve scendere;
- `behaviour`: non deve regredire;
- `cross_build`: non deve peggiorare.

Se OVER scende ma UNDER sale della stessa quantità, il difetto è stato
**spostato**, non corretto — ed è esattamente il tipo di risultato che un
singolo numero aggregato nasconderebbe.

## 18.5 Ordine di applicazione consigliato

Questa correzione va applicata **da sola**, non insieme alle altre due mosse: è
l'unica che tocca una primitiva condivisa, e mescolarla renderebbe impossibile
attribuire un eventuale spostamento delle metriche.

Ordine finale proposto:
1. mossa 0 (`behavior.py --json-out`) — dimezza il costo di tutte le misure
   successive, non tocca l'emissione;
2. mossa 2 (`JUMPOUT` → tail call) — chiude il requisito utente, effetto locale
   e verificabile a occhio;
3. **questa** — da sola, con i quattro criteri sopra.

---

# Round 19 — 2026-08-18 11:35 — La baseline è TAINTED: un altro agente edita lo stesso albero

## 19.1 Esito di `measure.sh --label base_0818`

```json
"tainted": true,
"fingerprint_before": "8b8672b85d03b7abc4d557f50c523070",
"fingerprint_after":  "61f65ebec263e8034342ca742bed299e",
```

L'albero sorgente è cambiato **durante** la misura. Per la regola dello
strumento stesso i numeri **non sono pubblicabili**. Circa un'ora di misura
persa.

**Non causato da me**: nessun sorgente toccato in 18 round, verificato a ogni
ciclo. Confermato dai `mtime`.

## 19.2 Chi si è mosso e quando

| file | modificato |
|---|---|
| `rustre-decompiler/src/binary_entry.rs` | 11:10:38 |
| `rustre-decompiler/src/lib.rs` | 11:11:45 |
| `rustre-decompiler/src/batch_decompiler.rs` | 11:11:45 |
| `rustre-decompiler/src/reconstruction/confidence.rs` | 11:11:45 |
| `rustre-il-lift/src/x86_handlers/mmx_sse.rs` | 11:07:06 |
| `rustre-il-lift/src/x86_handlers/control_flow.rs` | **11:30:34** |
| + `fpu_x87.rs`, `misc.rs`, `shifts.rs` | idem |

`git status` mostra modifiche su decine di crate in tutto il workspace
(`analysis-dataflow`, `analysis-vsa`, `arch-6502`, `agent-*`, `bin`, …):
è una campagna in corso, non un ritocco. Harness e `ida_defs.h` sono invece
**intatti** (mtime di luglio), quindi la contaminazione viene dai `.rs`.

## 19.3 Numeri del run tainted — NON PUBBLICABILI, ma indicativi

Registrati **solo** come indizio, con l'avvertenza esplicita che sono
inutilizzabili come baseline:

| metrica | valore (tainted) | riferimento noto |
|---|---|---|
| `c_files` | 11342 | = |
| `arity` | 122/135 (6 over, 7 under) | = |
| `fidelity` legacy | 14/16 | regressione già annotata (§1.6a) |
| `behaviour` | 15/63 | = |
| `duplicate_param` | 4 | = |
| `crossbuild_compared` | 1619 | era 1359 |
| **`crossbuild_inconsistent`** | **0** | **erano 2** |
| `unresolved_files` | 4717 | erano 5582 |
| `unresolved_actionable` | 4012 | erano 7329 |
| `unresolved_code_as_data` | 0 | classe `apply` confermata chiusa |
| **`data_symbols_defined`** | **5427** | **CLAUDE.md dice ZERO su path A** |

⚠ **`data_symbols_defined: 5427` supera una riga di CLAUDE.md**: path A NON
definisce più zero simboli dati. Il lavoro non committato (e/o quello
dell'altro agente) ha già aperto quella porta. Da rimisurare su un albero
stabile prima di trattarlo come acquisito.

## 19.4 Conseguenze operative

1. `base_0818` **non è utilizzabile** come termine di paragone.
2. Ogni nuova misura rischia la stessa sorte finché l'altra attività continua.
3. Applicare patch a `lib.rs` ora rischia di scontrarsi con modifiche
   concorrenti (vedi la regola «rileggere sempre i file prima di editare»).

## 19.5 Opzioni presentate all'utente

- **A** — attendere la fine dell'altra attività, poi rimisurare e applicare;
- **B** — lavorare comunque, accettando misure contaminate e rischio conflitti;
- **C** *(raccomandata)* — **git worktree isolato**: modifiche separate, misure
  non contaminate, integrazione successiva. Costo: una build release iniziale.

In assenza di risposta si prosegue in **sola lettura** (analisi e progettazione,
rischio nullo), con le patch progettate ma non applicate.

---

# Round 20 — 2026-08-18 — ✅ APPLICATE E VERIFICATE: mossa 0 e mossa 2

L'utente ha scelto l'**opzione B** (§19.5) e ha chiarito che le modifiche
concorrenti sull'albero sono **sue**: sta fixando e potenziando i crate. Si
procede quindi sull'albero condiviso, rimisurando più tardi su albero stabile.

## 20.1 Mossa 0 — APPLICATA: `behavior.py` eseguito una volta sola

- `tests/decompiler_corpus/behavior.py`: aggiunto `--json-out PATH`; il payload
  JSON (con il dettaglio per-funzione) è ora costruito **incondizionatamente** e
  scritto su file, mentre stdout resta il report testuale. Il ramo `--json`
  resta intatto per compatibilità.
- `tests/decompiler_corpus/measure.sh:157-158`: due invocazioni → **una**.
- Verificato: `ast.parse` OK, `bash -n` OK, il flag compare in `--help`.
- ⚠ **Verifica di equivalenza ANCORA DA FARE**: alla prossima misura completa,
  confrontare `behavior.txt`/`behavior.json` con quelli di `runs/base_0818`
  (prodotti dalla doppia esecuzione). Finché non è fatto, il guadagno atteso
  (~62 → ~32 min) è **previsto, non misurato**.

## 20.2 Mossa 2 — APPLICATA E VERIFICATA: `JUMPOUT` → tail call

Modificata la guardia a `lib.rs:17939` come progettato in §14.2: gli operandi di
memoria (`*v6`, `ptr->field_18`, `*(result + 32)`) vengono ora convertiti in
`return ({op})()`.

Build release: **OK** (8m42s).

### Risultato misurato, rigenerando i due bucket interessati

| verifica | prima | dopo |
|---|---|---|
| `sample10_cs` — `JUMPOUT` | 12 (in 6 file) | **0** |
| `sample5_cs` — `JUMPOUT` | 6 (in 6 file) | **0** |
| `goto` in entrambi | 0 | **0** (invariato) |
| file emessi `sample10_cs` | 2263 | 2263 (invariato) |

### Forma prodotta — il pass di cast ha fatto la sua parte

```c
__int64 __fastcall sub_1400034B0() {
    ...
    return ((__int64 (*)())(ptr->field_18))();
}
```
`cast_indirect_call_targets` ha avvolto l'operando parentesizzato col cast
corretto, come previsto in §14.2.

### Controllo anti-regressione: NON ho scambiato un difetto con un altro

Sui 6 file precedentemente affetti:
- `gcc -std=gnu89 -fsyntax-only -w`: **6/6 compilano**;
- `gcc -Werror=implicit-function-declaration`: **zero** dichiarazioni implicite
  residue. La `JUMPOUT` non dichiarata è sparita e **nulla l'ha sostituita**.

### Stato del requisito utente

**«0 goto e 0 JUMPOUT» → RAGGIUNTO** su entrambi i bucket che contenevano gli
unici 18 casi del corpus. Da confermare sull'intero corpus alla prossima
rigenerazione completa.

Effetto collaterale atteso e desiderato (§14.3): dove il `JUMPOUT` non era
l'ultima istruzione del blocco, le righe successive sono ora irraggiungibili —
correzione, non regressione, perché con `JUMPOUT` inesistente il C ricompilato
le eseguiva.

## 20.3 Restano da applicare

- **Mossa 3** (tassonomia lettura/scrittura AT&T, §18.3): da sola, con i quattro
  criteri di §18.4.
- Le mosse di cablaggio della catena (§4.6 voci 5-12).

---

# Round 21 — 2026-08-18 — ⛔ ANNULLATI i Round 16 e 17: `split_two` gestisce GIÀ l'AT&T

## 21.1 Cosa avevo "dimostrato" e perché è sbagliato

I Round 16-17 concludevano che i 4 parametri fantasma nascono dal classificatore
lettura/scrittura che prende il **primo** operando come destinazione, mentre
l'AT&T ha la destinazione per **ultima**. **Annullato.**

L'errore: avevo letto `RawMnemonicView::writes_register` (`pass_pipeline.rs:619`),
che è usata da `VariableRecoveryPass` — **non** dal rilevatore di parametri.
`win64_param_regs_live_in` usa una funzione diversa, `writes_reg`
(`lib.rs:2957`), con la sua `split_two` (`lib.rs:18054`).

## 21.2 Il codice VERO è corretto

`split_two` **rileva l'AT&T e inverte**:
```rust
if a.starts_with('%') || a.starts_with('$') || b.starts_with('%') || b.starts_with('$') {
    Some((b, a))      // AT&T → dst = SECONDO operando
} else {
    Some((a, b))      // Intel → dst = primo
}
```
Per `mov (%rbx), %edx`: `a = (%rbx)`, `b = %edx`; `b` inizia con `%` → ritorna
`(dst=%edx, src=(%rbx))`.

`writes_reg` ha inoltre **già** la tassonomia che avevo progettato in §18.3:
- lista esplicita di mnemonici scriventi (`mov`, `lea`, `add`, `pop`, …) —
  `cmp`/`test`/`push` **non** sono nella lista;
- `att_mnemonic_stem` per le forme con suffisso di taglia;
- destinazione in **memoria** (`dst.contains('(')`) → **non** è una scrittura di
  registro, con il commento che spiega il caso misurato;
- esiste un test dedicato, `writes_reg_sees_att_sized_writes` (`lib.rs:38908`).

E il predicato di **lettura** (`lib.rs` ~119 dentro `win64_param_regs_live_in`)
conta il registro come letto solo se compare nella SORGENTE, o in una
destinazione di memoria (dove è base d'indirizzo):
```rust
mentions_reg(src, alias) || (mentions_reg(dst, alias) && dst.contains('('))
```
Per `mov (%rbx), %edx` → `edx` NON è letto, ed è marcato scritto. **Corretto.**

## 21.3 Conseguenza: la causa dei 4 fantasmi è di nuovo IGNOTA

Ipotesi cadute finora su questo singolo difetto:
1. regola D9 (sonda muta, §15.2a);
2. arity sbagliata del chiamato (è 0 e corretta, §15.2b);
3. over-scan del corpo del chiamato (confine corretto, §15.2b);
4. **classificatore AT&T** (già corretto, questo round).

**La patch progettata in §18.3 NON va applicata**: replicherebbe una tassonomia
che esiste già, su una funzione diversa da quella responsabile.

## 21.4 Lezione di metodo — cambia l'approccio, non solo l'ipotesi

Quattro spiegazioni plausibili e sbagliate, tutte ottenute **leggendo il
codice**. Il codice di questo repo è denso, con più funzioni omonime che fanno
cose diverse (`writes_register` vs `writes_reg`, `analyze_stack_frame` in due
crate, §1.2): la lettura porta con facilità alla funzione sbagliata.

**Prossimo passo obbligato: strumentare, non leggere.** Aggiungere una sonda —
sulla falsariga di `RUSTRE_DBG_PARAMREG` già presente — che stampi, per una
funzione data, QUALE registro viene marcato parametro, a QUALE istruzione e per
QUALE regola. È l'unico modo per chiudere la questione, ed è il metodo che il
precedente autore aveva già adottato per lo stesso tipo di dubbio.

## 21.5 Nota positiva

Le mosse 0 e 2 restano valide e verificate (§20): erano fondate su misure
dirette (conteggi sul corpus, esecuzione del compilatore), non su lettura
interpretativa del codice. La differenza di affidabilità fra i due metodi è,
in questa sessione, netta e documentata.

---

# Round 22 — 2026-08-18 — Sonda #6630: le promozioni viste accadere

## 22.1 Strumentazione aggiunta (effetto ZERO sull'emissione)

Due `eprintln!` in `win64_param_regs_live_in`, dietro il gate esistente
`RUSTRE_DBG_PARAMREG`:
- `[PARAMREG-LIVEIN]` — quando un registro viene promosso a parametro: quale,
  a quale istruzione, con quale mnemonico;
- `[PARAMREG-WRITE]` — quando una scrittura viene riconosciuta (la promozione è
  vietata se il registro risulta già scritto, quindi servono entrambi).

Motivo: la LETTURA del codice aveva già prodotto **quattro** spiegazioni
plausibili e sbagliate (§21.3).

## 22.2 Risultato su `sample1.exe` — 105 promozioni totali

Per `_pei386_runtime_relocator` (`0x140001a00` = 5368715776):

```
[PARAMREG-WRITE]   scrive  a2 (rdx) @0x140001a93  mov (%rbx), %edx   (×3)
[PARAMREG-LIVEIN]  promuove a3 (r8)  @0x140001b75  sub %r8, %rax
[PARAMREG-LIVEIN]  promuove a4 (r9)  @0x140001b78  add %r9, %rax
[PARAMREG-LIVEIN]  promuove a1 (rcx) @0x140001b7b  and $0xc0, %ecx
[PARAMREG-WRITE]   scrive  a1 (rcx) @0x140001b7b  and $0xc0, %ecx
```

**Le scritture immediatamente precedenti non compaiono**:
```asm
0x140001b44  mov (%rbx), %r8d     ← scrive r8 — NON registrata
0x140001b47  mov 8(%rbx), %ecx    ← scrive rcx — NON registrata
0x140001b54  mov (%r8),  %r9      ← scrive r9 — NON registrata
```
Se lo fossero state, `if is_param[i] || written[i] { continue; }` avrebbe
impedito le tre promozioni.

Nota: `and $0xc0, %ecx` promuove **e** scrive — corretto, è
read-modify-write.

## 22.3 Cosa è stato escluso, verificandolo

- `writes_reg` (`lib.rs:2957`): lista mnemonici corretta, destinazione in
  memoria gestita, test dedicato — **corretto**;
- `split_two` (`lib.rs:18054`): rileva l'AT&T e inverte — **corretto**;
- `reg_width_aliases`: `r8` → `["r8","r8d","r8w","r8b"]` — **completo**;
- le istruzioni **esistono** nel corpo emesso: `sub_140001a00.c` contiene
  `a4 = iter->field_0;`, `a3 = iter->field_4;`, `a1 = iter->field_8;`, che
  corrispondono proprio a `b44`/`b47`/`b54`.

## 22.4 Unica spiegazione ancora compatibile

**Il flusso di istruzioni passato a `win64_param_regs_live_in` non coincide con
quello usato in emissione**: contiene `b75..b7b` ma non `b44..b54`. Sarebbe un
difetto di assemblaggio del flusso / confine di funzione a monte — imparentato
con l'incoerenza già osservata fra il range di `disasm_dump`
(`0x140001a00..=0x140001ac8`) e il corpo emesso, molto più esteso (§16.3), e con
la classe `INTERIOR_ADDRESS` (§7.3).

**Prossimo passo**: una terza sonda che stampi il flusso ricevuto (conteggio e
primo/ultimo indirizzo) per una funzione data, confrontandolo con il corpo
emesso. È l'unica misura che chiude la questione.

## 22.5 Conferma esterna delle mosse applicate

Audit indipendente dell'utente sul binario delle 11:45, su **3816 file**:

| marker | valore |
|---|---|
| **`JUMPOUT`** | **0** ✅ |
| **`goto`** | **0** ✅ |
| brace balance | 3816/3816 = 100% |
| ricompilabilità gcc | **99,71%** (3805/3816) |

I due zeri sono l'effetto della mossa 2 di §20.2 (erano 18 `JUMPOUT` in 12
file), confermato su un corpus più ampio e da una misura indipendente dalla mia.

L'audit segnala inoltre che un fix alle forward declaration (non mio) ha chiuso
86 delle 97 failure di ricompilabilità, e che le 11 residue sono di **tre classi
nuove e più profonde**: (A) mismatch SIMD `__m128i` → `double` (7 file),
(B) variabili dichiarate due volte con tipi in conflitto (3 file),
(C) prototipo di `_onexit` incoerente col prelude (2 file). Tutte e tre sono
difetti di **tipizzazione**, coerenti con il pattern dei DIVERGE (§11.4).

---

# Round 23 — 2026-08-18 — Due corpi diversi per la STESSA funzione

## 23.1 La misura

Terza sonda (`[PARAMREG-STREAM]`, stesso gate, effetto zero): stampa il flusso
ricevuto. Su `_pei386_runtime_relocator`:

```
[PARAMREG-STREAM] n=57   first=0x140001a00  last=0x140001ac8
[PARAMREG-STREAM] n=57   first=0x140001a00  last=0x140001ac8
[PARAMREG-STREAM] n=224  first=0x140001a00  last=0x140001b8f
```

**`win64_param_regs_live_in` è chiamata TRE volte sulla stessa funzione, con DUE
corpi diversi**: 57 istruzioni (fino a `0x140001ac8`) e 224 (fino a
`0x140001b8f`).

Il confine a `0x140001ac8` è **esattamente** quello che riportava `disasm_dump`
(§16.3) — quindi i due rilevatori di confine coesistono nello stesso processo e
danno risultati diversi. Le promozioni fantasma avvengono nella **terza**
chiamata, quella da 224.

## 23.2 Perché è un difetto a sé, indipendente dai parametri fantasma

Un'analisi «letto prima di scritto» dà risultati diversi su corpi diversi. Con
due rilevatori di confine attivi, **quale risposta vince dipende dall'ordine
delle chiamate**, non dal binario. È la stessa famiglia dell'incoerenza
`INTERIOR_ADDRESS` (§7.3), dove un target di jump table interno veniva promosso
a punto d'ingresso di funzione.

## 23.3 Ipotesi residua sui fantasmi: flusso NON in ordine di indirizzo

Nel flusso da 224 istruzioni, `b44`/`b47`/`b54` sono **dentro l'intervallo**
(`a00..b8f`) ma le loro scritture non vengono mai registrate, mentre le letture
a `b75`/`b78`/`b7b` sì.

Unica spiegazione compatibile con tutto ciò che è stato verificato
(`writes_reg`, `split_two`, `reg_width_aliases` tutti corretti, §22.3):
**il flusso non è ordinato per indirizzo**. Se il blocco che contiene `b75`
precede quello che contiene `b44`, «letto prima di scritto» dà per forza la
risposta sbagliata.

Precedente nel repo che rende l'ipotesi credibile: `arities_from_seeds`
(`binary_entry.rs`) documenta un bug identico — l'iterazione su una `HashMap`
aveva ordine randomizzato per processo, e la stessa VA convergeva ad arità
diverse fra due esecuzioni sullo stesso binario; risolto ordinando per VA. **Lo
stesso rimedio potrebbe valere qui.**

## 23.4 Verifica che chiude la questione (una riga)

Estendere `[PARAMREG-STREAM]` a stampare i primi ~10 indirizzi in ordine di
flusso, oppure semplicemente:
```rust
let sorted = instructions.windows(2).all(|w| w[0].address <= w[1].address);
```
Se `sorted == false`, la causa è dimostrata e il rimedio è ordinare il flusso
prima dell'analisi (non riordinare l'emissione, che ha ragioni proprie).

## 23.5 Stato delle sonde

Le tre sonde `#6630` restano nel codice: gated su `RUSTRE_DBG_PARAMREG`, effetto
**zero** sull'emissione, e sono l'unico strumento che ha prodotto un risultato
dopo quattro ipotesi cadute per sola lettura. Il repo ha già questo precedente
(`RUSTRE_DBG_PARAMREG` esisteva per lo stesso tipo di dubbio).

---

# Round 24 — 2026-08-18 — Le primitive rispondono `true` in ESECUZIONE, e la scrittura non viene registrata

## 24.1 Ipotesi ordine-flusso: FALSIFICATA (quinta caduta)

Sonda estesa con `sorted = instructions.windows(2).all(|w| w[0].address <= w[1].address)`:

```
[PARAMREG-STREAM] n=57  first=0x140001a00 last=0x140001ac8 sorted=true
[PARAMREG-STREAM] n=224 first=0x140001a00 last=0x140001b8f sorted=true
```
**133 flussi nel binario, 0 non ordinati.** E `n == distinti` (224/224): nessun
duplicato, nessun buco di indirizzi.

## 24.2 Le istruzioni ci sono, e le primitive dicono `true`

Sonda `[PARAMREG-WIN]` con la valutazione **reale** delle primitive:

```
@0x140001b44 mov (%rbx), %r8d    [r8d:w=true]
@0x140001b47 mov 8(%rbx), %ecx   [ecx:w=true]
@0x140001b54 mov (%r8), %r9      [r8:w=false r9:w=true]
@0x140001b75 sub %r8, %rax       → PROMOSSO a parametro
```

`writes_reg` risponde **`true`** su tutte e tre, in esecuzione, con gli operandi
reali. E funziona in generale: nello stesso binario registra **40** scritture di
`r8`, 28 di `r9`, 29 di `rcx`, 53 di `rdx`.

Verificate una per una e tutte corrette: `writes_reg`, `split_two`,
`mentions_reg` (confini di parola giusti su `%r8d`), `att_mnemonic_stem`
(`mov` → `mov`), `reg_width_aliases` (`r8` → `r8/r8d/r8w/r8b`).
Il vecchio probe D9 stampa **0** righe: confermato che non è coinvolto (§15.2a).

## 24.3 La contraddizione, allo stato

Perché la scrittura venga saltata serve che `is_param[2] || written[2]` sia già
vero a `b44` — ma:
- `written[2]` vero avrebbe stampato una riga `[PARAMREG-WRITE]` prima: non c'è;
- `is_param[2]` vero avrebbe impedito anche la promozione a `b75`: che invece
  avviene.

Il ciclo principale non ha `break` (verificato). Non ci sono duplicati né buchi.
**La contraddizione non è ancora spiegata.**

## 24.4 Un buco nella strumentazione, trovato per strada

Nella funzione ci sono **quattro** punti che impostano lo stato:

| riga | assegnamento | sonda |
|---|---|---|
| 2565 | `is_param[i] = true` (regola D9) | sì (preesistente) |
| **2601** | **`written[i] = true`** (ramo `zeroes_itself`) | **NO** |
| 2664 | `is_param[i] = true` (lettura pura) | sì (`#6630`) |
| 2685 | `written[i] = true` (scrittura) | sì (`#6630`) |

La riga **2601 registra scritture in silenzio**. Non spiega `b44` (che è un
`mov`, non un `xor`/`sub` auto-azzerante), ma è un buco da chiudere: qualunque
analisi delle sonde è cieca su quel percorso.

## 24.5 Prossima misura (una sola, poi si decide)

Stampare lo **stato delle guardie** (`is_param[i]`, `written[i]`) per ogni
istruzione della finestra `b40..b80`, prima del `continue`. È l'unica cosa che
resta da vedere: o una delle due è vera — e allora va scoperto chi l'ha
impostata — oppure il ciclo non passa da lì, e il problema è a un livello
ancora diverso.

## 24.6 Bilancio di questo filone

Ipotesi cadute su un singolo difetto: **cinque** (D9, arity del chiamato,
over-scan, sintassi AT&T, ordine del flusso). Quattro per sola lettura del
codice, una per misura.

Ma le sonde hanno prodotto due risultati collaterali di valore indipendente:
- **due rilevatori di confine di funzione discordanti** sulla stessa funzione
  (57 vs 224 istruzioni, §23.1) — difetto reale, riproducibile, mai notato;
- un **punto di scrittura non strumentato** (riga 2601).

Nota di costo: ogni ciclo di build è passato da ~16s a ~9 min man mano che
l'albero condiviso veniva modificato in parallelo. La strumentazione va
progettata per rispondere a più domande insieme, non una alla volta.

---

# Round 25 — 2026-08-18 — La risposta: i registri erano GIÀ promossi

## 25.1 La misura decisiva

Sonda unica (`[PARAMREG-GUARD]`) che stampa lo stato delle guardie prima del
`continue`, applicando la lezione di §24.6 (una sonda che risponde a tutto,
invece di quattro build in serie):

```
@0x140001b44 mov (%rbx), %r8d
    is_param=[true, false, true, true]   written=[true, true, false, false]
```

**`rcx` (a1), `r8` (a3) e `r9` (a4) sono GIÀ promossi a parametro prima di
`0x140001b44`.** La guardia `if is_param[i] || written[i] { continue; }` scatta,
e le scritture non vengono mai valutate.

**Il difetto non era «una scrittura non riconosciuta»: era una promozione
anticipata.** Cercavo il contrario di quello che succedeva.

Controllo di unicità: 16 righe GUARD, 16 istruzioni distinte, `b44` compare
**una sola volta** → una sola invocazione copre quella finestra, e vi entra con
tre registri già decisi.

## 25.2 Dove cercare adesso

La promozione avviene **prima di `0x140001b40`**, cioè nell'intervallo
`0x140001a00..0x140001b40` — 320 byte, che il flusso da 224 istruzioni copre.
Prossimo passo: allargare la finestra della sonda GUARD a tutta la funzione e
leggere la PRIMA istruzione in cui ciascun registro passa a `true`.

## 25.3 Incoerenza residua fra le due sonde — dichiarata, non risolta

`[PARAMREG-LIVEIN]` stampa le promozioni a `b75`/`b78`/`b7b`; `[PARAMREG-GUARD]`
dice che erano già vere a `b44`. Le due cose non stanno insieme in una singola
invocazione: se `is_param[2]` fosse vero a `b44`, a `b75` il `continue`
impedirebbe la promozione e la LIVEIN non stamperebbe.

Ipotesi non verificata: le due sonde stanno fotografando **invocazioni diverse**
— coerente con il difetto già isolato in §23.1 (tre invocazioni sulla stessa
funzione, con corpi da 57, 57 e 224 istruzioni). La sonda GUARD **non stampa
l'indirizzo della funzione**, quindi allo stato non è distinguibile.

Correzione da fare: aggiungere `fn=` alla GUARD. È il difetto della sonda, non
del decompilatore.

## 25.4 Perché mi fermo qui su questo filone

Sette build su un singolo difetto, cinque ipotesi cadute, e il ritorno marginale
è in calo. Ma il filone ha prodotto risultati indipendenti che restano:

1. **Due rilevatori di confine di funzione discordanti** sulla stessa funzione
   (§23.1) — difetto reale, riproducibile, mai documentato prima.
2. **Un punto di scrittura non strumentato** (riga 2601, ramo `zeroes_itself`).
3. La causa dei fantasmi ristretta da «ignota» a **«promozione anticipata
   nell'intervallo a00..b40»** — un bersaglio di 320 byte invece dell'intero
   decompilatore.
4. Quattro sonde permanenti, gated, a effetto zero, che chiunque può riusare.

Costo da annotare: i build sono passati da 16 s a 9 min mentre l'albero
condiviso veniva modificato in parallelo. Su un albero conteso, **il costo di
una domanda non è il pensiero ma la compilazione**: le sonde vanno progettate
per rispondere a molte domande insieme.

## 25.5 Workflow avviato

Lanciato `catena-decompiler-100` (run `wf_4bcfcded-35b`): dodici agenti mappano
un crate ciascuno, poi ogni proposta di cablaggio passa da un agente incaricato
di **refutarla** (default `survives=false` in caso di dubbio), infine sintesi in
un piano ordinato per valore/rischio.

Scelta deliberata: **gli agenti NON scrivono codice.** L'utente sta editando lo
stesso albero in parallelo (§19.2); dodici agenti che scrivono insieme
corromperebbero il suo lavoro e renderebbero impossibile attribuire le
regressioni. Producono piani verificati e patch pronte, che vengono applicate in
sequenza con la misura in mezzo.

Trappole passate agli agenti perché non ripetano gli errori di oggi: import
aliasati in `analysis_bridge.rs` (falsi negativi al grep del percorso completo),
path B spento di default, funzioni omonime in crate diversi.

---

# Round 26 — 2026-08-18 — ✅ CAUSA RADICE DEI PARAMETRI FANTASMA: scansione lineare invece del CFG

## 26.1 La misura che chiude

Sonda GUARD resa configurabile (`RUSTRE_DBG_PARAMREG_WIN=<lo>:<hi>` esadecimale)
e dotata di `fn=` + `n=`, così si distingue QUALE invocazione parla. Estratte le
prime transizioni `false -> true` di ciascun parametro:

```
[n=57]  stato iniziale [false,false,false,false] @ 0x140001a00
[n=224] stato iniziale [false,false,false,false] @ 0x140001a00
[n=224]   a3: false -> true  @ 0x140001af4  add %r9, %rax
[n=224]   a4: false -> true  @ 0x140001af7  and $0xC0, %ecx
[n=224]   a1: false -> true  @ 0x140001afd  mov %rax, -8(%rbp)
```

La sonda stampa lo stato PRIMA di elaborare l'istruzione, quindi ogni transizione
appartiene all'istruzione PRECEDENTE:

| parametro | promosso elaborando |
|---|---|
| `a3` (r8) | `~0x140001af1  sub %r8, %rax` |
| `a4` (r9) | `0x140001af4  add %r9, %rax` |
| `a1` (rcx) | `0x140001af7  and $0xC0, %ecx` |

**Non a `b75`/`b78`/`b7b` come sembrava** (§22.2): a `af1..af7`, cioè a indirizzi
PIÙ BASSI di `b44`, dove stanno le scritture. Le stesse tre istruzioni compaiono
DUE volte nel flusso (`af1..af7` e `b75..b7b`): è un blocco di ciclo.

Si risolve così anche l'incoerenza dichiarata in §25.3: le due sonde NON
fotografavano invocazioni diverse — fotografavano **due occorrenze dello stesso
blocco** a indirizzi diversi.

## 26.2 La causa

A `0x140001b63` c'è `jbe 0x140001AD0`: un salto **all'indietro**. Quindi
`ad0..b6c` è un CICLO, e `b44` (che scrive `r8`) sta dentro il ciclo.

- **Ordine di ESECUZIONE**: `b44` scrive `r8`, il back-edge riporta a `af1` che
  lo legge → `r8` NON è un parametro, la funzione lo definisce da sé.
- **Ordine di INDIRIZZO** (quello che l'analisi usa): `af1` viene prima di `b44`
  → «letto prima di essere scritto» → **promosso a parametro**.

**`win64_param_regs_live_in` scorre le istruzioni in ordine di indirizzo, non in
ordine di flusso di controllo.** Per un ciclo in cui la scrittura sta a un
indirizzo più alto di una lettura, la risposta è l'esatto contrario della verità.

Questo spiega anche perché il difetto sia intermittente: colpisce solo le
funzioni con quella forma di ciclo, non tutte.

## 26.3 La correzione è il cablaggio della catena

Una liveness corretta richiede il CFG con i back-edge, non una scansione
lineare. La funzione esiste già ed è testata:

**`rustre-analysis-dataflow::compute_liveness`** — nel crate di cui il
decompilatore raggiunge **4 nomi su 404 elementi pubblici** (§1.1).

Esiste anche il ponte: `analysis_bridge::build_liveness_cfg_from_mlil`
(`analysis_bridge.rs`) — che al momento **non ha chiamanti** (§Round 1, elenco
delle funzioni morte dentro il bridge).

I parametri fantasma non sono quindi un bug da rattoppare in `win64_param_regs_live_in`:
sono il **sintomo di un'analisi di liveness riscritta a mano in forma lineare**,
mentre il crate che la fa correttamente sul grafo è presente, testato e
inutilizzato. È la tesi generale di questo STATUS (§1.1-1.2), qui dimostrata su
un difetto specifico e misurato.

## 26.4 Perché questo cambia la priorità di `analysis-dataflow`

Nel Round 1 `analysis-dataflow` era in coda come «difensivo: può solo salvare
variabili, non aggiungere fedeltà» (§4.6 voce 7 / §1.1). **Rivalutato**: la sua
`compute_liveness` corregge una causa dimostrata di:
- `fidelity` 14/16 (la regressione `_pei386_runtime_relocator`, §1.6a);
- parte dei **6 OVER** di `arity` 122/135;
- plausibilmente parte dei **9756 OVER** di `callsite_consistency` (da misurare,
  non assumere).

## 26.5 Come misurarla

Sostituire la scansione lineare con la liveness su CFG è un cambio a una
primitiva condivisa: va fatto **da solo**, con i criteri di §18.4 —
`arity` OVER deve scendere **e UNDER non deve salire**; se OVER scende e UNDER
sale della stessa quantità il difetto è stato spostato, non corretto.

## 26.6 Bilancio del filone

Sei ipotesi cadute (D9, arity del chiamato, over-scan, sintassi AT&T, ordine del
flusso, scrittura non riconosciuta) prima della causa vera. Tutte e sei
plausibili; nessuna reggeva a una misura.

Ciò che ha funzionato: **una sola sonda che stampa lo stato completo e
configurabile**, invece di quattro sonde che rispondono a una domanda ciascuna.
La lezione di §24.6, applicata, ha chiuso in un colpo un filone aperto da sette
round.

---

# Round 27 — 2026-08-18 — Correzione #6640 tentata, MISURATA ROSSA, messa dietro gate

## 27.1 Cosa ho implementato

Guardia in `win64_param_regs_live_in`: rilevamento dei **back-edge** dal flusso di
istruzioni (salto con target <= indirizzo del salto), mappa degli indirizzi in
cui ciascun registro argomento viene scritto, e soppressione della promozione
quando lettura e scrittura cadono **nello stesso ciclo**.

Effetto sul caso studio, misurato: `_pei386_runtime_relocator` da **4 parametri
fantasma a 2**; la guardia scatta **25 volte** in `sample1`.

## 27.2 MA la misura complessiva è ROSSA

`fidelity_arity.py` sul sottoinsieme `sample1` (10 prototipi controllati):

| | prima | dopo |
|---|---|---|
| correct | 8 | **7** |
| OVER | 1 | 1 |
| UNDER | 1 | **2** |

**OVER non scende e UNDER sale.** È esattamente il modo di fallire previsto in
§18.4: *«se OVER scende ma UNDER sale della stessa quantità, il difetto è stato
SPOSTATO, non corretto»*. Qui è anche peggio — OVER non si è mosso affatto.

## 27.3 Perché l'euristica non può funzionare (e cosa dimostra)

La guardia non sa distinguere due situazioni **opposte** con la stessa forma
sintattica:

| caso | verità |
|---|---|
| (a) la scrittura precede la lettura via back-edge | il registro NON è un parametro |
| (b) la lettura precede la scrittura alla PRIMA iterazione | il registro **È** un parametro |

Entrambi appaiono come «lettura e scrittura nello stesso ciclo». Distinguerli
richiede **liveness vera con dominanza**, cioè
`rustre_analysis_dataflow::compute_liveness` sul CFG — crate presente, testato,
di cui il decompilatore raggiunge 4 nomi su 404.

**Questa misura è la prova sperimentale che un'euristica lineare non basta**, e
quindi un argomento diretto a favore del cablaggio del crate: non «sarebbe più
elegante», ma «l'alternativa è stata provata e ha regredito».

## 27.4 Come l'ho chiusa

Gate `RUSTRE_PARAMREG_LOOPGUARD`, **opt-in, default OFF**. Verificato dopo il
rebuild: con il gate spento l'arity torna **identica alla baseline**
(correct 8, over 1, under 1) e la firma torna a 4 parametri — output ripristinato.

Non cancellata perché: la **diagnosi resta valida** (§26 — causa radice
dimostrata), la guardia è il banco di prova pronto per quando la liveness su CFG
verrà cablata, e il commento in-source registra il numero rosso così nessuno
la riaccende senza sapere.

## 27.5 Nota di metodo

È la prima correzione di questa sessione applicata e poi **ritirata su misura**.
Le due precedenti (mossa 0 e mossa 2) erano verificate: JUMPOUT 18→0 con 6/6 file
che compilano e zero dichiarazioni implicite residue. La differenza non è la
fortuna: quelle erano **misurabili in modo diretto** (conteggi, esecuzione del
compilatore), questa richiedeva un giudizio su cosa sia «vero» parametro — e lì
un'euristica sbaglia.

---

# Round 28 — 2026-08-18 — Workflow ricalibrato: 30 sopravvissuti su 48

Rilanciato con la soglia corretta (`survives=TRUE` di default, bocciatura solo
con prova citabile), riusando dalla cache le 12 mappature. Le prime voci del
piano, con punto di aggancio **ri-verificato**:

| # | componente | aggancio | difetto | sforzo/rischio |
|---|---|---|---|---|
| 1 | `CfsValidator::validate` (`decompiler-cfs:2680`) | `lib.rs:19335` dopo `structurer.structure(entry)` | **oracolo**: distingue «goto 0 perché perfetto» da «blocchi scartati in silenzio» | basso/basso |
| 2 | `index_count_evidence` (typerecov) | `lib.rs:19710` / filtro 5033-5049 | CRASH dimostrato: parametro-lunghezza promosso a puntatore | basso/basso |
| 3 | `populate_mingw_runtime` (154 firme) | gate `RUSTRE_LIBSIG_ARITY` + override `win64_recovered_arity` | **UNDER=7**: `_Unwind_FindEnclosingFunction` | basso/basso |
| 5 | `DefUseChains` (dataflow) | produzione `lib.rs:28606`, consumo 19842→15067 | DIVERGE da versione errata | basso/basso |
| 7 | `scan_array_accesses_x86` + `infer_element_size` | `lib.rs:4899` | **DIVERGE dimostrato: elem size 8 invece di 1/4** | medio/medio |
| 10 | `MlilCallAnalysis::analyze_function` | `lib.rs:27912` | callsite_consistency 9756 OVER | medio/medio |
| 20 | `adf::ssa::construct_ssa` | `lib.rs:19547` (path A, non gated) | versione registro sbagliata; **abilita 5, 10, 11, 16** | alto/medio |

Voce **1** è notevole e non l'avevo considerata: `CfsValidator` non chiude un
difetto, è un **oracolo** che direbbe se i nostri `goto 0` sono merito dello
structuring o effetto di blocchi scartati in silenzio. Prima di festeggiare uno
zero conviene sapere quale dei due è.

⚠ Il piano segnala anche che **`RUSTRE_HLIL` è una primitiva condivisa da ~20
gate** (`_RESOLVE`, `_CODE_PTR`, `_SUB_NAMES`, `_RETYPE_VOID`, `_FALLBACK`,
`_CFS`, `_TAILDUP`, `_SWITCH`, `_DEADTMP`…): accenderla attiva decine di
comportamenti insieme e rende **non attribuibile** qualunque regressione. La
commutazione a path B va fatta a scaglioni, non con un interruttore.

---

# Round 29 — 2026-08-18 — Due scoperte: una scorciatoia di misura, e una frase falsa in CLAUDE.md

## 29.1 ⚡ `sample7_cpp` contiene TUTTI i 135 prototipi

```
python fidelity_arity.py <solo sample7_cpp> --json
  {"checked": 135, "correct": 122, "over": 6, "under": 7,
   "not_present_in_build": 0, "pct": 90.37}
```

**Identico al numero dell'intero corpus** (§1.5). Un solo bucket (994 file,
~40 s di rigenerazione) riproduce la metrica di arity di 11342 file.

**Conseguenza operativa grossa**: per iterare sull'arity non serve
`measure.sh` completo (~32 min anche dopo la mossa 0). Bastano:
```
dump_decompile.exe bin/sample7_cpp.exe <dir>/sample7_cpp
python fidelity_arity.py <dir> --json
```
Da usare per il ciclo stretto; `measure.sh` resta per la validazione finale e
per le metriche che quel bucket non copre (behaviour, cross_build, unresolved).

## 29.2 ❌ `RUSTRE_LIBSIG_ARITY` NON fa quello che CLAUDE.md dice

Esperimento eseguito su `sample7_cpp`:

| | checked | correct | over | under |
|---|---|---|---|---|
| gate OFF | 135 | 122 | 6 | 7 |
| **gate ON** | 135 | **122** | **6** | **7** |

**Effetto ZERO.** E `_Unwind_FindEnclosingFunction` resta
`__int64 __fastcall _Unwind_FindEnclosingFunction()` — zero parametri, contro il
prototipo pubblicato di 1.

### Perché

`published_lib_arity` ha **un solo chiamante**, a `lib.rs:19274`, dentro il
blocco che semina l'arità dei **CALL SITE**:
```rust
if let Some(tgt) = direct_call_target(ins).or_else(|| direct_tail_jump_target(ins))
    && !extra.contains_key(&tgt)
    && let Some(raw) = resolver.resolve(tgt)
```
Decide **quanti argomenti passa una chiamata**, non con quanti parametri una
funzione viene **DEFINITA**. `fidelity_arity.py` misura le DEFINIZIONI, la cui
arità viene da `win64_recovered_arity` — che il gate non tocca.

### La frase falsa

CLAUDE.md (sezione «The cheapest open experiment in the repo — ZERO lines of
code») afferma che il gate è la ragione per cui
`_Unwind_FindEnclosingFunction` esce con 0 parametri mentre la firma giusta è
nel database. **Falso su due punti**: il gate non agisce sulle definizioni, e
accenderlo non muove nulla — misurato, non dedotto.

Il ragionamento sottostante resta valido (le 154 firme esistono, sono corrette,
e non vengono usate per le definizioni); sbagliato è il **punto di intervento**.
Quello giusto è l'alternativa (b) indicata dal workflow:
**`binary_entry.rs:1372/1377`, override di `win64_recovered_arity(_with)`** —
cioè far vincere il prototipo pubblicato sull'inferenza da liveness quando il
nome è risolto con certezza.

⚠ Attenzione al rischio, già scritto nel commento in-source di
`published_lib_arity`: un prototipo pubblicato che vince su un'arità recuperata
**introduce argomenti fantasma se il nome risolto è sbagliato**. L'override va
misurato su OVER **e** UNDER insieme (§18.4).

## 29.3 Terzo caso in questa sessione di «il difetto sta nella frase»

1. CLAUDE.md: «path A definisce ZERO simboli dati» → misurato **5427** (§19.3);
2. CLAUDE.md: «behaviour 7/14» → è la vecchia scala, oggi **15/63** (§1.5);
3. CLAUDE.md: «il gate `RUSTRE_LIBSIG_ARITY` è la ragione dei 0 parametri» →
   **effetto zero, agisce su un altro asse** (questo round).

In tutti e tre i casi il *ragionamento* era corretto e il *fatto* superato. È il
motivo per cui questo STATUS annota sempre la fonte e la data di ogni numero.

---

# Round 30 — 2026-08-18 — ✅ PRIMO GUADAGNO DI FEDELTÀ MISURATO: arity 122 → 128 su 135

## 30.1 Cosa ho implementato (#6650)

`apply_win64_calling_convention_with` (`lib.rs`) usa ora il **prototipo
pubblicato come LIMITE INFERIORE** dell'arità della DEFINIZIONE, dietro il gate
`RUSTRE_PROTO_ARITY` (opt-in, default OFF).

Due funzioni nuove:
- `signature_fn_name(code)` — estrae il nome dalla riga di firma, con la guardia
  contro `if`/`while`/`for`/`switch` (un matcher `(…) {` prende anche quelli:
  trappola documentata in CLAUDE.md);
- `published_arity_ungated(name)` — stessa sorgente di `published_lib_arity`
  (`LibrarySignatureDb`, 154 firme mingw-w64 estratte dagli header) ma **senza**
  il gate di quella, che governa un asse diverso (i CALL SITE, §29.2).

**Asimmetria deliberata: alza soltanto, mai abbassa.** Un'arità troppo BASSA
perde argomenti reali e rompe le chiamate; una troppo ALTA inventa parametri
fantasma che compilano puliti e sono invisibili a `check.sh`. Alzare è
recuperabile, abbassare no.

## 30.2 Misura su `sample7_cpp` (il bucket che contiene tutti i 135 prototipi, §29.1)

| | correct | OVER | UNDER | pct |
|---|---|---|---|---|
| baseline | 122 | 6 | 7 | 90,37 |
| **`RUSTRE_PROTO_ARITY=1`** | **128** | **6** | **1** | **94,81** |

**UNDER 7 → 1. OVER invariato a 6.** È esattamente la forma richiesta dai criteri
di §18.4: gli UNDER scendono e gli OVER **non salgono**. Il difetto è stato
corretto, non spostato — al contrario del tentativo del Round 27, che con gli
stessi criteri risultò rosso e fu messo dietro gate.

`_Unwind_FindEnclosingFunction`, che CLAUDE.md descrive come «perfettamente
consistente e uniformemente sbagliata» (0 parametri in ogni build contro un
prototipo di 1), ora esce:
```c
__int64 __fastcall _Unwind_FindEnclosingFunction(__int64 a1) {
```

## 30.3 Controlli anti-regressione

| controllo | esito |
|---|---|
| compilazione (120 file, `gcc -std=gnu89 -fsyntax-only -w`) | **120/120 ok**, identico alla baseline |
| `sample1` — arity | **identico** (8 correct, 1 over, 1 under) |
| `sample1` — callsite_consistency | **identico** (5 OVER, 21 UNDER) |
| `sample7_cpp` — callsite_consistency | 161→160 OVER, 203→204 UNDER (**neutro, ±1**) |

Lo scambio ±1 su `callsite_consistency` è **spiegato**: la correzione tocca le
DEFINIZIONI, non i call site. Una funzione che guadagna un parametro e continua
a essere chiamata con zero argomenti genera un UNDER interno. È un'informazione,
non un difetto nuovo: dice che l'altro lato va allineato.

## 30.4 `RUSTRE_LIBSIG_ARITY` è confermato inerte, anche in combinazione

| | arity | callsite |
|---|---|---|
| solo `PROTO_ARITY` | 128/135 | 160/204 |
| **entrambi i gate** | **128/135** | **160/204** |

Identici. Il gate dei call site non muove nulla nemmeno insieme all'altro,
confermando §29.2: non è «spento per prudenza», è **senza effetto misurabile**
sull'asse che le metriche osservano.

## 30.5 Perché resta opt-in (per ora)

Manca la validazione su **`behaviour`**: aggiungere un parametro a una
definizione cambia ciò che la funzione legge quando l'harness la **compila,
linka ed esegue**. Un parametro in più letto come spazzatura può trasformare un
AGREE in un DIVERGE, e nessuna delle metriche misurate qui lo vedrebbe.

Condizione per il default-ON: una `measure.sh` completa su albero **stabile**
(oggi è conteso, §19) con `behaviour` non in regressione. Numeri e criteri sono
tutti qui sopra: chi la esegue non deve ri-derivare nulla.

## 30.6 Nota di metodo — cosa ha fatto la differenza

Il Round 27 (guardia sui cicli) e questo round hanno la stessa struttura:
diagnosi, implementazione, misura. Uno è fallito, l'altro no. La differenza non
è la fortuna:

- il Round 27 richiedeva di **decidere se un registro è un parametro** — un
  giudizio semantico che un'euristica sintattica non può fare;
- questo round **non decide nulla**: prende una risposta già scritta e verificata
  (il prototipo estratto meccanicamente dagli header) e la usa come limite.

Dove esiste una fonte di verità, usarla batte qualunque euristica. Ed è
esattamente l'argomento a favore del cablaggio della catena: quei crate SONO
fonti di verità già scritte e verificate.

---

# Round 31 — 2026-08-18 — CAUSA SISTEMATICA DEI 5 OVER `pthread_*`: arity da funzioni `noreturn`

## 31.1 Il pattern che ha innescato l'indagine

I 6 OVER di `sample7_cpp` si dividono in due gruppi:
- `_pei386_runtime_relocator`: want 0, got 4 (il caso dell'ordine nei cicli, §26);
- **5 × `pthread_*`: tutte con esattamente +2 parametri** (`want 2, got 4` ×4;
  `want 1, got 3` ×1).

«+2 su cinque funzioni della stessa famiglia» non è rumore: è una causa
sistematica.

E l'unico UNDER residuo, `__mingw_raise_matherr` (want 5, got 4), **non è un
bug**: Win64 passa 4 argomenti in registro e il quinto sullo stack. Il limite
`published <= 4` di #6650 ha fatto bene a rifiutarlo. È un limite strutturale
del recupero, che modella solo i registri.

## 31.2 Catena di eliminazione, misurata

| ipotesi | verifica | esito |
|---|---|---|
| `a3`/`a4` usati nel corpo | grep su `pthread_join` | **mai usati**, solo in firma |
| promossi dai registri INTERI | sonda `[PARAMREG-LIVEIN]` | **no**: promuove solo a1/a2 |
| promossi dal file XMM | sonda `[PARAMREG-XMM]` aggiunta | **no**: 30 attivazioni nel bucket, **zero** per `pthread_join` |
| promossi dalla regola **D9** | sonda `[PARAMREG]` preesistente | **SÌ** |

```
[PARAMREG] fn=pthread_join callee=0x140011230 arity=4 accende a3
[PARAMREG] fn=pthread_join callee=0x140011230 arity=4 accende a4
```

⚠ Correzione al §15.2a: avevo concluso «la regola D9 non scatta mai» dopo aver
misurato su `sample1`, dove `callee_arities` è vuota. Su `sample7_cpp` scatta
**476 volte**. La conclusione era corretta per quel bucket e **generalizzata a
torto**.

## 31.3 La causa: `__stack_chk_fail` con arity 4

I callee più propagati:
```
85 × callee=0x140011230 arity=4     <- __stack_chk_fail
48 × callee=0x14002bec0 arity=4
46 × callee=0x14002bc50 arity=4
46 × callee=0x140022170 arity=4
42 × callee=0x140022430 arity=4
```

`0x140011230` è **`__stack_chk_fail`**, che di parametri ne prende **ZERO**.

Perché la liveness ne ricava 4: è `noreturn`. Non ritorna mai — salta nel
gestore — quindi i registri che il corpo «legge prima di scrivere» sono quelli
che il **chiamante** ha lasciato vivi, non i suoi parametri. L'arità che ne esce
è un **artefatto**, e D9 la propaga verso l'alto su 85 call site.

`__stack_chk_fail` **non è** nei prototipi pubblicati, quindi la strada delle
firme (#6650) non lo copre.

## 31.4 La correzione (#6670): stessa forma della guardia thunk già esistente

Il repo ha già il precedente esatto: D9-THUNK (#6600) rimuove i thunk d'import
dalla mappa delle arità perché «un thunk non ha un corpo da cui ricavare
un'arità», con la motivazione *«meglio NESSUNA evidenza di una FALSA»*.

Aggiunta la guardia gemella in `arities_from_seeds` (`binary_entry.rs`), gate
`RUSTRE_NORETURN_NO_ARITY` (opt-in):
```rust
order.retain(|va| !crate::detect_noreturn(&bodies[va]));
```
`detect_noreturn` esisteva già (`lib.rs:6117`), promossa a `pub(crate)`. Il
bucket contiene **231** funzioni già riconosciute `__noreturn`.

**È una regola semantica, non un'euristica**: una funzione che non ritorna non
ha parametri osservabili per liveness. La differenza rispetto al tentativo
fallito del Round 27 è la stessa del Round 30: qui non si *indovina*, si
riconosce una proprietà che il decompilatore già determina.

## 31.5 Da misurare

Attesa: i 5 OVER `pthread_*` scendono; OVER totale 6 → 1 (resta
`_pei386_runtime_relocator`, di causa diversa). **Da verificare**, e insieme che
UNDER non salga — se D9 smette di propagare arità *corrette* da qualche noreturn,
si perdono argomenti veri.

Ciclo di misura: `sample7_cpp` + `fidelity_arity.py` (§29.1), ~40 s per giro.

---

# Round 32 — 2026-08-18 — La guardia `noreturn` non serve: quelle funzioni RITORNANO (7ª ipotesi caduta)

## 32.1 Misura

| | correct | OVER | UNDER |
|---|---|---|---|
| baseline | 122 | 6 | 7 |
| `PROTO_ARITY` | 128 | 6 | 1 |
| **`PROTO_ARITY` + `NORETURN_NO_ARITY`** | **128** | **6** | **1** |

Nessun effetto. Verificato con la sonda: **476 attivazioni D9 con la guardia
accesa, 476 con la guardia spenta** — la `retain` non rimuove nulla.

## 32.2 Perché: `detect_noreturn` ha ragione a non riconoscerle

Disassemblato `0x140011230`:
```asm
0x140011280  sub  $0x38, %rsp
0x140011284  mov  %r9, 0x58(%rsp)     <- spill di r9 nello shadow space
0x140011289  lea  0x58(%rsp), %r9     <- indirizzo dello spill
0x14001128e  mov  %r9, 0x28(%rsp)
0x140011293  call 0x1400112A0
0x140011298  add  $0x38, %rsp
0x14001129c  ret                       <- RITORNA
```

La funzione **ritorna**. `detect_noreturn` cerca «ultima istruzione significativa
= `call` seguita solo da `ud2`/`int3`/`hlt`/padding» e qui trova `ret`:
comportamento **corretto**. La mia regola era valida in generale e
**inapplicabile a questo caso**.

## 32.3 Il pattern vero: prologo di salvataggio registri di una VARIADICA

`mov %r9, 0x58(%rsp)` + `lea 0x58(%rsp), %r9` + passaggio dell'indirizzo è il
prologo che costruisce una **`va_list`**. Una funzione variadica legge
legittimamente tutti e quattro i registri argomento: la sua arity 4 è **corretta
per lei**, ed è sbagliato che D9 la propaghi a chiamanti che variadici non sono.

Regola corretta, da implementare al posto di quella `noreturn`:
**D9 non deve propagare l'arità da un callee VARIADICO.** `published_lib_arity`
già scarta le variadiche (`if sig.is_variadic { return None }`), ma qui il callee
è noto per VA e non per nome, quindi serve il riconoscimento del prologo.

## 32.4 Secondo reperto: il simbolo è attribuito male

Il file emesso per quell'indirizzo dichiara
`__int64 __fastcall __stack_chk_fail()`. Ma `__stack_chk_fail` non costruisce
una `va_list` e non ritorna: **il nome non c'entra con questo corpo**. C'è quindi
un difetto di attribuzione dei simboli su questo indirizzo, indipendente
dall'arità — e potenzialmente più grave, perché un nome sbagliato inquina ogni
ragionamento che vi si appoggia (incluso il mio di §31.3).

## 32.5 Stato della guardia #6670

Tenuta, `RUSTRE_NORETURN_NO_ARITY` default OFF, con questa nota: la regola è
semanticamente valida (una funzione che non ritorna non ha parametri osservabili
per liveness) ma **misurata a effetto zero su `sample7_cpp`**, perché i callee
responsabili non sono `noreturn`. Non riaccenderla aspettandosi un guadagno su
questo bucket.

## 32.6 Bilancio ipotesi

Settima ipotesi caduta della sessione. Ma il costo è stato basso — una guardia di
tre righe e due misure da 40 secondi — perché il ciclo veloce di §29.1 era già
in piedi. La stessa ipotesi al Round 15 sarebbe costata un'ora.

---

# Round 33 — 2026-08-18 — ✅ SECONDO GUADAGNO: arity 122 → 131 su 135 (OVER 6 → 3)

## 33.1 La guardia variadica (#6680)

`ha_prologo_variadico` in `binary_entry.rs`: riconosce il salvataggio di un
registro argomento nello shadow space seguito dal `lea` dell'**indirizzo dello
stesso slot** — la costruzione di una `va_list`. I callee così riconosciuti
vengono rimossi dalla mappa delle arità (`order.retain`), esattamente come i
thunk d'import (#6600).

Gate `RUSTRE_VARIADIC_NO_ARITY`, opt-in.

### Un difetto MIO, trovato misurando

Prima versione: finestra limitata alle prime 16 istruzioni. **Effetto zero**
(476 attivazioni D9 prima e dopo). Causa: nel caso che aveva motivato la guardia
(`0x140011230`) la coppia `mov`/`lea` sta a `0x140011284`, ~0x54 byte dopo
l'ingresso — **fuori dalla finestra**. Allargata a tutto il corpo: il pattern
resta specifico (il `lea` deve puntare *esattamente* allo slot salvato) e un
falso positivo costa solo «nessuna evidenza di arità», la direzione prudente.

## 33.2 Misura su `sample7_cpp`

| | correct | OVER | UNDER | pct |
|---|---|---|---|---|
| baseline | 122 | 6 | 7 | 90,37 |
| `PROTO_ARITY` (#6650) | 128 | 6 | 1 | 94,81 |
| **`PROTO_ARITY` + `VARIADIC_NO_ARITY`** | **131** | **3** | **1** | **97,04** |

**OVER 6 → 3, UNDER fermo a 1.** Entrambe le direzioni nella forma richiesta dai
criteri di §18.4.

## 33.3 Controlli

| controllo | esito |
|---|---|
| compilazione (120 file) | **120/120**, come la baseline |
| `callsite_consistency` | OVER 161→**204**, UNDER 203→**95**, totale 364→**299** |

⚠ Il totale delle incoerenze **scende di 65**, ma gli OVER **salgono di 43**
mentre gli UNDER crollano di 108. È coerente con l'intervento: le definizioni
hanno guadagnato parametri (#6650) e le arità dei callee variadici sono sparite
(#6680), quindi più call site passano ora *più* argomenti di quanti la
definizione dichiari. **Netto positivo, ma non uniforme** — va detto, non
nascosto dietro il totale.

## 33.4 I 3 OVER rimasti, con causa

| funzione | want/got | causa |
|---|---|---|
| `_pei386_runtime_relocator` | 0/4 | ordine di indirizzo nei cicli (§26) — serve liveness su CFG |
| `pthread_cond_signal` | 1/3 | il terzo parametro esce `double` → file XMM (§31.2), non ancora indagato |
| `pthread_mutex_timedlock32` | 2/4 | da indagare |

## 33.5 Riepilogo dei guadagni misurati della sessione

| intervento | metrica | prima | dopo |
|---|---|---|---|
| `JUMPOUT` → tail call (#6620) | `JUMPOUT` nel corpus | 18 | **0** |
| — | `goto` | 0 | 0 (invariato) |
| `behavior.py` una sola esecuzione | costo di una misura completa | ~62 min | ~32 min (atteso) |
| `PROTO_ARITY` + `VARIADIC_NO_ARITY` | arity su `sample7_cpp` | 122/135 | **131/135** |
| — | UNDER | 7 | **1** |
| — | OVER | 6 | **3** |

Tutti e tre i gate nuovi sono **opt-in**: il default-ON richiede una `measure.sh`
completa con `behaviour` su albero stabile (§30.5).

---

# Round 34 — 2026-08-18 — 🔴 L'ORACOLO RISPONDE: lo `0 goto` è in parte PERDITA DI CODICE

## 34.1 Cablato `CfsValidator` (#6700)

`rustre_decompiler_cfs::CfsValidator::validate(ast, blocks)` — presente nel
crate, **mai chiamato dal decompilatore** — verifica che l'AST strutturato
contenga TUTTI i blocchi di partenza e altrimenti riporta `missing blocks: [...]`.

Agganciato in `emit_structured_code` subito dopo `structurer.structure(entry)`,
gate `RUSTRE_CFS_VALIDATE`, **effetto zero sull'emissione**. Il clone dei blocchi
avviene solo a gate acceso (`ControlFlowStructurer` ne prende possesso).

## 34.2 La domanda che poneva

Il corpus emette **0 `goto` su 11342 file** — meglio di Hex-Rays, e confermato da
un audit indipendente dell'utente su 3816 file. Ma quello zero ha **due cause
possibili e opposte**:
- **(a)** lo structuring chiude davvero ogni regione;
- **(b)** i blocchi non strutturabili vengono **scartati in silenzio**, e i loro
  `goto` spariscono con essi.

Nessuna metrica esistente distingue i due casi.

## 34.3 Risposta: è (b), su circa una funzione su sei

| bucket | funzioni con blocchi PERSI | su totale | % |
|---|---|---|---|
| `sample7_cpp` | **193** | 994 | **19,4%** |
| `sample1` | 7 | 43 | 16,3% |
| `sample6_c` | 7 | 49 | 14,3% |
| `sample11_c` | 8 | 51 | 15,7% |

## 34.4 Il pattern è SISTEMATICO: si perde l'ULTIMO blocco

```
___w64_mingwthr_add_key_dtor    7 blocchi -> missing [BlockId(6)]    <- l'ultimo
__mingw_TLScallback            18 blocchi -> missing [BlockId(17)]   <- l'ultimo
_gnu_exception_handler         31 blocchi -> missing [BlockId(30)]   <- l'ultimo
_FindPESectionByName           12 blocchi -> missing [BlockId(10), BlockId(11)]
__do_global_ctors               9 blocchi -> missing [BlockId(8)]    <- l'ultimo
___w64_mingwthr_remove_key_dtor 13 blocchi -> missing [BlockId(12)]  <- l'ultimo
_matherr                       11 blocchi -> missing [BlockId(10)]   <- l'ultimo
```

Distribuzione su `sample7_cpp` (quanti blocchi persi per funzione):

| blocchi persi | funzioni |
|---|---|
| **1** | **155** |
| 2 | 18 |
| 3 | 7 |
| 4 | 4 |
| 5 / 6 | 1 / 1 |
| **15** | 1 |
| **17** | 1 |

155 su 193 perdono **esattamente un blocco, l'ultimo**. Due funzioni ne perdono
15 e 17 — quelle sono perdite gravi.

Nota: `drop_empty_blocks` gira **prima** e il validatore confronta l'AST con i
blocchi che ha ricevuto DOPO quella potatura. Quindi i blocchi qui riportati non
sono blocchi vuoti già scartati: sono blocchi passati allo structurer e non
ricomparsi nell'AST.

## 34.5 Perché è importante

1. **Ridimensiona un risultato di punta.** Lo `0 goto` non è interamente merito
   dello structuring: una parte è codice che non c'è più.
2. **È una firma plausibile per i 12 CRASH e gli 11 DIVERGE** (§5.1): una
   funzione a cui manca l'ultimo blocco — tipicamente epilogo, `ret`, o un ramo
   d'uscita — compila benissimo e si comporta male. Esattamente il profilo di
   «confidently wrong» che `check.sh` non vede.
3. **Nessuna metrica esistente lo vedeva.** Serviva un oracolo, e stava nel crate
   inutilizzato — il caso più netto della tesi di questo STATUS: la capacità
   c'era, mancava il cablaggio.

## 34.6 Da fare

- Verificare se il blocco perso è **raggiungibile**: un blocco morto scartato è
  corretto, un ramo d'uscita perso no. `CfsValidator` non lo distingue.
- Le due funzioni con 15 e 17 blocchi persi vanno guardate per prime: lì la
  perdita non può essere benigna.
- Incrociare l'elenco delle funzioni con blocchi persi con i 12 CRASH e gli 11
  DIVERGE di `behavior.py`: se si sovrappongono, la causa è trovata.

⚠ Il gate resta opt-in ed è **diagnostico**: non corregge nulla, misura. Ma è la
prima cosa da tenere accesa in un ciclo di lavoro sullo structuring.

---

# Round 35 — 2026-08-18 — ⚠ RIDIMENSIONAMENTO del §34.5: la perdita di blocchi NON spiega i DIVERGE

## 35.1 L'incrocio

§34.5 affermava che la perdita di blocchi era «una firma plausibile per i 12
CRASH e gli 11 DIVERGE». **Verificato, e i dati non la sostengono.**

Funzioni con blocchi persi, per bucket:

| bucket | funzioni con blocchi persi |
|---|---|
| `sample6_c` | `__mingw_TLScallback`, `___w64_mingwthr_add_key_dtor`, `_matherr`, `__do_global_ctors`, `_FindPESectionByName`, `___w64_mingwthr_remove_key_dtor`, `_gnu_exception_handler` |
| `sample1` | le stesse sette |
| `sample11_c` | le stesse + **`matrix_trace`** |

Funzioni testate da `behavior.py`:

| bucket | funzioni |
|---|---|
| `sample6_c` | `classify`, `factorial`, `apply`, `count_set_flags`, `dot` |
| `sample11_c` | `dispatch`, `punned_bits`, `pack_fields`, `my_strlen`, `matrix_trace` |
| `sample1` | `accumulate`, `find_max` |

**Nessuna delle funzioni con DIVERGE dimostrato perde blocchi.** `classify`,
`my_strlen`, `apply`, `count_set_flags` non compaiono nell'elenco. Le loro cause
restano quelle isolate ai §26, §11, §9: difetti di **tipo** e di versione
registro.

## 35.2 E una sovrapposizione che smentisce l'ipotesi

`matrix_trace` (`sample11_c`) **perde blocchi** ed è testata dal comportamento.
Il suo esito in `behavior.txt` è **`AGREE  matrix_trace  (3 curated)`**.

Quindi **almeno una perdita di blocchi è benigna**: il blocco scartato era morto,
e la funzione si comporta correttamente. `CfsValidator` dice che un blocco manca,
**non** che servisse.

## 35.3 Cosa resta valido del §34, e cosa va corretto

**Resta valido:**
- il fatto misurato: **~15-19% delle funzioni perde blocchi** durante lo
  structuring (193/994 in `sample7_cpp`);
- il pattern: 155 su 193 perdono **esattamente l'ultimo blocco**;
- il ridimensionamento dello `0 goto`: una parte di quello zero è codice che non
  compare nell'AST, non structuring riuscito;
- il valore del cablaggio: l'oracolo stava nel crate inutilizzato e nessuna delle
  sei metriche esistenti vedeva questa classe.

**Va corretto:** l'ipotesi che questa perdita spieghi i fallimenti
comportamentali. **Non dimostrata, e un controesempio (`matrix_trace` AGREE) la
indebolisce.**

## 35.4 Le due domande ancora aperte

1. **Il blocco perso è raggiungibile?** Un blocco morto scartato è corretto; un
   ramo d'uscita perso no. Serve un'analisi di raggiungibilità sul CFG di
   partenza — di nuovo `rustre-analysis-cfg`, con `reachable_from` fra i 355
   elementi inutilizzati.
2. **Le due funzioni che perdono 15 e 17 blocchi**: lì la perdita non può essere
   benigna, e vanno guardate per prime.

## 35.5 Nota di metodo

Il §34 è stato scritto con l'entusiasmo di un dato forte (19% di funzioni con
codice perso) e ci ha attaccato una spiegazione plausibile mai verificata. Un
solo incrocio l'ha smontata in due minuti.

È la stessa lezione delle otto ipotesi cadute, applicata a un risultato **mio e
positivo** invece che a una diagnosi altrui: un dato vero non autorizza la
conclusione che gli sta comoda accanto.

---

# Round 36 — 2026-08-18 — 🔴 La perdita di blocchi è MOLTO peggiore di quanto misurato al §34

## 36.1 ⚠ Il conteggio del §34.4 era SBAGLIATO — mio errore

Il §34.4 riportava «155 funzioni perdono esattamente 1 blocco». **Falso.** Quel
conteggio faceva `awk -F',' '{print NF}'` sull'**intera riga di log**, che
contiene altre virgole oltre a quelle dentro `missing blocks: [...]`.

Rifatto estraendo il contenuto delle parentesi (`cfsdist.py` in scratchpad).

## 36.2 I numeri veri su `sample7_cpp`

| | |
|---|---|
| funzioni con blocchi persi | **169** su 994 |
| blocchi persi | **623** su 4935 nelle stesse funzioni = **12%** |

Distribuzione per **frazione del corpo perduta**:

| perdita | funzioni |
|---|---|
| **≥75% del corpo** | **4** |
| 50-74% | 9 |
| 25-49% | 5 |
| <25% | 23 |
| esattamente 1 blocco | 128 |

I casi peggiori, con nome:

| funzione | persi / totali | % |
|---|---|---|
| `sub_1400128F4` | 32 / 34 | **94%** |
| `__mingw_pformat` | **131 / 164** | 79% |
| `read_encoded_value_with_base` | 17 / 22 | 77% |
| `d_type` | 76 / 115 | 66% |
| `sub_140006194` | 74 / 118 | 62% |
| `sub_14001F250` | 68 / 133 | 51% |

## 36.3 Lettura corretta

Il difetto ha **due popolazioni distinte**, e mescolarle nasconde quella grave:

1. **128 funzioni perdono 1 solo blocco.** Probabilmente benigno: `matrix_trace`
   è in questa fascia e il suo esito comportamentale è **AGREE** (§35.2).
2. **18 funzioni perdono ≥25% del corpo, 4 ne perdono ≥75%.** Qui non può essere
   codice morto: `__mingw_pformat` è l'implementazione di `printf`, e il file
   emesso è di 180 righe con 131 blocchi su 164 mancanti — un **guscio**.

Il §34 aveva quindi ragione sul fatto (la perdita esiste ed è diffusa) e torto
sulla forma (non è «quasi sempre un blocco solo»).

## 36.4 Perché nessuna metrica lo vedeva

Un corpo mutilato **compila perfettamente**: `check.sh` non se ne accorge.
`fidelity_arity.py` guarda la firma, non il corpo. `callsite_consistency` conta
argomenti. `cross_build` confronta build fra loro, e se la mutilazione è
uniforme le trova tutte d'accordo.

Solo `behaviour` potrebbe vederlo — ma nessuna delle 63 funzioni testate è tra le
18 gravi, quindi **non lo vede neanche lui**. È un difetto che il corpus attuale
non copre.

## 36.5 Prossimi passi

1. Capire **perché** lo structurer scarta: `ControlFlowStructurer::structure`
   restituisce un AST che non contiene quei blocchi. Se la causa è una regione
   irriducibile non gestita, il rimedio esiste già nella catena
   (`decompiler-cfs::LoopStructurer`, `analysis-cfg::LoopForest`, entrambi
   inutilizzati).
2. **Aggiungere una funzione mutilata al `behavior_spec.json`**, così la
   metrica comportamentale copre questa classe. Oggi il corpus è cieco proprio
   dove il difetto è più grave.
3. Distinguere blocco morto da blocco raggiungibile
   (`analysis-cfg::reachable_from`, inutilizzato).

---

# Round 37 — 2026-08-18 — ✅ LO STRUCTURER È INNOCENTE: scarta esattamente i blocchi IRRAGGIUNGIBILI

## 37.1 La misura

Esteso l'oracolo #6700 con il calcolo della raggiungibilità dall'entry sui
blocchi che lo structurer riceve (BFS sui `successors`):

| funzione | blocchi | raggiungibili | persi | superstiti (blocchi − persi) |
|---|---|---|---|---|
| `__mingw_pformat` | 164 | **33** | 131 | **33** |
| `d_type` | 115 | **39** | 76 | **39** |
| `read_encoded_value_with_base` | 22 | **5** | 17 | **5** |
| `sub_1400128F4` | 34 | **2** | 32 | **2** |

**I superstiti coincidono ESATTAMENTE con i raggiungibili, in tutti e quattro i
casi.**

## 37.2 Conclusione: il difetto non è dove lo cercavo

`ControlFlowStructurer` scarta **precisamente** i blocchi irraggiungibili
dall'entry. È il comportamento corretto: non perde codice vivo.

Il §34 e il §36 attribuivano la perdita allo structuring. **Sbagliato.** Il
difetto è **a monte**: il CFG contiene blocchi non collegati — 131 su 164 in
`__mingw_pformat`.

## 37.3 Secondo indizio: i blocchi sono troppi

`__mingw_pformat` occupa `0x1400133a0..0x14001359c` = **508 byte** secondo
`disasm_dump`, ma il CFG ne conta **164 blocchi**: ~3 byte per blocco,
impossibile per x86-64.

Due spiegazioni, non mutuamente esclusive:
- gli **archi di successione** non vengono calcolati per alcune forme di salto,
  e ogni blocco resta orfano;
- il **confine di funzione** include codice che non le appartiene — e c'è già un
  precedente misurato: due rilevatori di confine discordanti sulla stessa
  funzione (57 vs 224 istruzioni, §23.1).

## 37.4 Dove intervenire

Non nello structurer. Nella **costruzione del CFG** —
`build_cfg_from_instructions_with_tables` (§1.3), che trova i leader di blocco
con `ins.mnemonic.to_lowercase()` e `parse_hex_target(ins.operands.trim())`, cioè
**parsando stringhe di disassemblato**. Una forma di salto non riconosciuta dal
parser testuale produce esattamente questo: blocco senza archi → irraggiungibile
→ scartato → codice perso.

Gli strumenti per farlo bene sono nella catena inutilizzata:
`rustre-analysis-cfg` (355 elementi su 400 mai chiamati) con `reachable_from`,
`LoopForest`, le frontiere di dominanza; e il CFG costruito sul **MLIL** invece
che sul testo.

## 37.5 Valore della sequenza §34 → §37

Quattro round per arrivare da «0 goto, meglio di Hex-Rays» a una causa precisa:
1. §34 — l'oracolo rivela che il 19% delle funzioni perde blocchi;
2. §35 — l'incrocio smentisce che spieghi i DIVERGE;
3. §36 — il conteggio corretto mostra che 4 funzioni perdono ≥75% del corpo;
4. §37 — la raggiungibilità scagiona lo structurer e sposta il difetto sul CFG.

Ogni passo ha corretto il precedente. Nessuno dei quattro sarebbe stato possibile
senza cablare un componente che era già scritto e non veniva chiamato.

---

# Round 38 — 2026-08-18 — Il punto sensibile: i leader di blocco nascono da un parse di STRINGHE

## 38.1 Il codice

`build_cfg_from_instructions_with_tables` (`lib.rs:811`) individua i leader così:

```rust
for ins in instructions {
    let m = ins.mnemonic.to_lowercase();
    if is_branch_mnemonic(&m)
        && let Some(t) = parse_hex_target(ins.operands.trim())
    {
        jump_targets.insert(t);
    }
}
```

Più i target delle jump table già risolte.

## 38.2 Perché produce blocchi orfani

Un salto il cui operando **non è un esadecimale semplice** non produce alcun
target:
- salto indiretto (`jmp *%rax`, `jmp *(%rdx,%rcx,8)`);
- salto attraverso registro o memoria;
- qualunque forma che `parse_hex_target` non copra.

Il blocco che ne sarebbe la destinazione **non riceve un arco entrante da
nessuno** → resta orfano → risulta irraggiungibile → lo structurer lo scarta
(correttamente, §37) → il codice sparisce dall'output **senza alcun segnale**.

È il meccanismo compatibile con i 131 blocchi scollegati su 164 di
`__mingw_pformat` (§36.2).

## 38.3 La conseguenza generale

**Il CFG di path A nasce da un parsing di stringhe di disassemblato.** Ogni forma
di salto non prevista dal parser testuale diventa codice perso in silenzio — e
nessuna metrica lo vede, perché il risultato compila.

È la stessa fragilità già osservata altrove:
- i leader trovati con `ins.mnemonic.to_lowercase()` (§1.3);
- l'analisi di liveness che scorre in ordine di indirizzo (§26);
- due rilevatori di confine di funzione discordanti (§23.1).

Tutte e tre hanno la stessa radice: **path A ragiona sul TESTO del disassemblato,
non su un IR**.

## 38.4 Dove porta

Il rimedio non è aggiungere casi al parser — sarebbe rincorrere le forme una per
una. È costruire il CFG **sul MLIL**, dove un salto indiretto è un nodo tipizzato
e non una stringa da riconoscere. Cioè: **path B**.

Questo è il quarto difetto indipendente che punta nella stessa direzione, ed è la
giustificazione tecnica più forte trovata finora per l'obiettivo dell'utente
(«path B unico»): non è una preferenza architetturale, è che path A non ha
l'informazione necessaria.

Strumenti pertinenti, tutti nella catena inutilizzata:
`rustre-analysis-cfg` (355/400 inutilizzati) per archi e raggiungibilità,
`rustre-analysis-vsa` per i target indiretti, `build_mlil_cfg` (già chiamata, il
suo output non alimenta l'emissione, §1.3).

---

# Round 39 — 2026-08-18 — ⚠ RIBALTAMENTO: i blocchi «persi» sono codice di ALTRE funzioni

## 39.1 La misura che cambia tutto

Disassemblato `__mingw_pformat` (`0x1400133a0`):

| | |
|---|---|
| istruzioni della funzione | **129** |
| range | `0x1400133a0..=0x14001359c` (508 byte) |
| salti condizionali | 19 |
| `jmp` diretti | 2 |
| `jmp` indiretti | **1** (`jmp *%rdx`) |
| **blocchi nel CFG** | **164** |
| **blocchi raggiungibili** | **33** |

Con 129 istruzioni e 22 salti in tutto **non si possono avere 164 blocchi**.
Ma **33 blocchi per 129 istruzioni fanno ~4 istruzioni per blocco**, che è la
densità normale.

## 39.2 Conclusione corretta

Il flusso di istruzioni passato al costruttore del CFG **contiene molto più
codice della funzione**. I 131 blocchi «persi» sono in gran parte **codice di
ALTRE funzioni**, che lo structurer scarta correttamente perché irraggiungibile
dall'entry di questa.

**`__mingw_pformat` è probabilmente emessa CORRETTAMENTE.** I 33 blocchi
superstiti sono i suoi.

## 39.3 Cosa va corretto dei §34-38

| affermazione | esito |
|---|---|
| §34: «lo `0 goto` è in parte perdita di codice» | **da ridimensionare**: è in parte scarto di codice ESTRANEO |
| §36: «4 funzioni perdono ≥75% del corpo» | **falso**: non perdono il proprio corpo, scartano corpo altrui |
| §37: «lo structurer scarta esattamente gli irraggiungibili» | **confermato e corretto** |
| §38: «i leader nascono da un parse di stringhe» | **vero come fatto**, ma NON è la causa di questo fenomeno (un solo `jmp *%rdx` in tutta la funzione) |

## 39.4 Il difetto vero, di nuovo lo stesso

**Over-scan del confine di funzione.** È il difetto già misurato al §23.1 —
`win64_param_regs_live_in` invocata tre volte sulla stessa funzione con corpi da
57, 57 e 224 istruzioni — e ricompare qui in forma più visibile: un flusso che
copre 164 blocchi dove la funzione ne ha 33.

Conseguenze già osservate dello stesso difetto:
- arità recuperate su corpi sbagliati (§23.2);
- l'analisi di liveness che vede istruzioni di altre funzioni;
- ora: CFG gonfiati di blocchi estranei.

## 39.5 Cosa resta valido e utile

- **L'oracolo `CfsValidator` funziona ed è prezioso**: ha portato a scoprire
  l'over-scan da una direzione indipendente. Va tenuto acceso.
- La misura di raggiungibilità aggiunta alla sonda è ciò che ha permesso di
  distinguere «perdita» da «scarto corretto». Senza, la conclusione allarmante
  del §34 sarebbe rimasta in piedi.
- **La domanda aperta**: le 128 funzioni che perdono UN SOLO blocco. Lì l'over-scan
  non spiega nulla (un blocco solo), e `matrix_trace` — che è in quella fascia —
  risulta `AGREE`. Probabilmente benigno, **non verificato**.

## 39.6 Nota di metodo — quinta correzione dello stesso filone

§34 (allarme) → §35 (non spiega i DIVERGE) → §36 (conteggio sbagliato, mio) →
§37 (structurer innocente) → §39 (è codice altrui).

Cinque round, cinque conclusioni, ognuna che corregge la precedente. Il valore
non è nell'ultima: è che ogni passaggio è stato **misurato e scritto**, quindi
nessuno dovrà ripercorrerlo. Ma il costo è reale, e la lezione operativa è che un
dato sorprendente va confrontato con una grandezza indipendente PRIMA di
costruirci sopra una diagnosi — qui bastava contare le istruzioni della funzione.

---

# Round 40 — 2026-08-18 — ✅ L'over-scan è VOLUTO e CORRETTO — ma inquina le analisi senza filtro

## 40.1 L'esperimento

Esiste già il gate `RUSTRE_PDATA_EXTENT` (default ON), che semina l'estensione
della scansione con la fine DICHIARATA in `.pdata` «così un `jmp` in avanti dopo
il primo `ret` non tronca la funzione».

| | con `.pdata` (default) | senza (`=0`) |
|---|---|---|
| `__mingw_pformat` — blocchi | **164** | **26** |
| `__mingw_pformat` — raggiungibili | **33** | **22** |
| `sub_1400128F4` | 34 blocchi / 2 raggiungibili | **assente** (nessuna perdita) |
| funzioni con blocchi persi (bucket) | 193 | 164 |

## 40.2 Confronto con la grandezza indipendente

`disasm_dump` dà **129 istruzioni** per `__mingw_pformat`.

- con `.pdata`: **33 blocchi raggiungibili ≈ 132 istruzioni** → **combacia**;
- senza: 22 blocchi ≈ 88 istruzioni → la funzione è **TRONCATA**.

**L'estensione `.pdata` fa esattamente il suo lavoro.** I 131 blocchi in più sono
codice vicino tirato dentro dalla scansione, e il filtro di raggiungibilità dello
structurer li elimina correttamente.

## 40.3 Conclusione: nessun difetto nell'EMISSIONE

**over-scan + filtro di raggiungibilità = risultato corretto.**
`__mingw_pformat` è emessa bene. Spegnere `RUSTRE_PDATA_EXTENT` la
peggiorerebbe (troncamento).

Questo chiude definitivamente il filone §34-§39: **non c'era perdita di codice.**

## 40.4 MA il costo lo pagano le analisi senza filtro

Il flusso completo (164 blocchi, 224 istruzioni al §23.1) viene passato **anche**
alle analisi che NON filtrano per raggiungibilità:

- `win64_param_regs_live_in` — calcola «letto prima di scritto» su istruzioni di
  **altre funzioni**;
- `win64_recovered_arity` — idem;
- `arities_from_seeds` — costruisce le arità dei callee sugli stessi flussi
  gonfiati.

È il collegamento che mancava fra due difetti che sembravano indipendenti:
**i parametri fantasma (§26, §31) e l'over-scan (§23.1, §39.4) sono lo stesso
fenomeno visto da due lati.** Lo structurer si difende con la raggiungibilità;
le analisi di liveness no.

## 40.5 Il rimedio, e perché è esattamente il cablaggio della catena

Le analisi di liveness/arity devono ricevere **solo i blocchi raggiungibili
dall'entry**, come già fa lo structurer. Serve quindi la raggiungibilità sul CFG
**prima** delle analisi, non solo dentro lo structuring.

Strumento: `rustre-analysis-cfg::reachable_from` — fra i **355 elementi
inutilizzati su 400** di quel crate. Oppure il CFG MLIL (`build_mlil_cfg`, già
chiamata, il cui output non alimenta path A).

Il rimedio ha un test di verifica immediato e già pronto: se funziona, i
parametri fantasma di `_pei386_runtime_relocator` (want 0, got 4) devono
scendere, e `arity` OVER da 3 verso 1.

## 40.6 Bilancio del filone §34-§40

Sette round. Conclusione finale: **nessun difetto dove sembrava, un difetto
reale altrove**, e i due difetti che sembravano separati sono uno solo.

Il valore netto:
- una classe di allarme falso chiusa definitivamente (perdita di codice);
- un collegamento causale nuovo fra over-scan e parametri fantasma;
- un rimedio preciso con criterio di verifica già misurabile;
- l'oracolo `CfsValidator` cablato, che ha reso possibile tutto questo.

Costo: sette round. La regola operativa che ne esce, già scritta al §39.6:
**confrontare un dato sorprendente con una grandezza indipendente PRIMA di
costruirci una diagnosi.** Qui la grandezza era «quante istruzioni ha la
funzione», e costava trenta secondi.

---

# Round 41 — 2026-08-18 — Filtro di raggiungibilità cablato: funziona, ma NON muove l'arity

## 41.1 Cosa ho implementato (#6710)

`reachable_instruction_addrs` — visita ricorsiva del flusso dall'ingresso
(fallthrough tranne dopo salto incondizionato o `ret`; target dei salti diretti
risolvibili; un salto indiretto interrompe il fallthrough senza aggiungere
target). Applicata in `apply_win64_calling_convention` prima delle analisi di
liveness, gate `RUSTRE_LIVEIN_REACHABLE` (opt-in).

Idea: dare alle analisi di liveness la stessa difesa che
`ControlFlowStructurer` ha già (§37).

## 41.2 Il filtro FUNZIONA

Sonda `[LIVEIN-REACH]` su `sample7_cpp`:

| | |
|---|---|
| invocazioni | 994 |
| **in cui il filtro rimuove istruzioni** | **435** (44%) |
| esempi | `330 -> 319`, `53 -> 49`, `44 -> 43` |

## 41.3 Ma l'arity NON cambia

| | correct | OVER | UNDER |
|---|---|---|---|
| senza filtro (§33) | 131 | 3 | 1 |
| **con filtro** | **131** | **3** | **1** |

## 41.4 L'ipotesi del §40.4 NON regge

§40.4 sosteneva che «i parametri fantasma e l'over-scan sono lo stesso fenomeno
visto da due lati». **Non confermato.**

Il motivo, visibile nei numeri della sonda: le riduzioni sono **modeste** — una
decina di istruzioni per funzione — mentre il gonfiore osservato al §39 era nei
**blocchi del CFG** (164 contro 33 raggiungibili), che arrivano da un percorso
diverso. Il flusso passato alla liveness è già quasi pulito.

Quindi i 3 OVER residui hanno un'altra causa, ancora da trovare.

## 41.5 Cosa resta

- Lo strumento è cablato, testato e **misurato a effetto zero sull'arity**: non
  va acceso aspettandosi un guadagno lì. Puo' servire ad altre analisi che
  ricevono lo stesso flusso (`win64_recovered_arity`, `arities_from_seeds`) —
  non verificato.
- Da capire: **perché il CFG ha 164 blocchi se il flusso ha ~129 istruzioni**.
  I due numeri non sono compatibili, e la spiegazione «il flusso è gonfio» è
  appena stata smentita. Probabile che i blocchi nascano da `jump_targets` che
  include indirizzi FUORI dal flusso (target di jump table), creando blocchi
  senza istruzioni.
- I 3 OVER rimasti: `_pei386_runtime_relocator` (0/4), `pthread_cond_signal`
  (1/2 dopo #6690), `pthread_mutex_timedlock32` (2/4).

## 41.6 Nota

Terza ipotesi caduta in questo filone, ma il costo è stato basso: un'ora fra
implementazione e misura, e resta uno strumento riutilizzabile. La differenza
rispetto ai round 15-24 è che ora ogni ipotesi si verifica in 40 secondi invece
che in un'ora — la scorciatoia di misura del §29.1 ha cambiato l'economia del
lavoro.

---

# Round 42 — 2026-08-18 — 🎯 LOCALIZZATA la lacuna che causa il DIVERGE `my_strlen`

## 42.1 Il codice macchina dà DUE segnali, entrambi inequivocabili

`my_strlen` (`sample11_c`, `0x140001550`):
```asm
0x140001550  cmpb $0, (%rcx)     <- suffisso 'b': accesso a memoria di 1 BYTE
0x140001555  mov  %rcx, %rax
0x140001560  add  $1, %rax       <- passo di 1
0x140001564  cmpb $0, (%rax)     <- 1 BYTE
0x140001569  sub  %rcx, %rax
```
Elemento da **1 byte** → `char *`. Sia la larghezza dell'accesso sia il passo lo
dicono.

## 42.2 Cosa emette il decompilatore

```c
__int64 __fastcall my_strlen(char *a1) {   // <- PARAMETRO corretto
    __int64 *result;                        // <- LOCALE sbagliato (8 byte)
    result = (__int64 *)a1;
    do { ++result; } while (*result != 0);  // avanza di 8, legge 8
```

Il **parametro** è tipizzato bene, la **variabile di ciclo** no. Due percorsi
diversi: uno cablato, l'altro no.

## 42.3 La lacuna, esatta

`att_mem_access_width(mnem, ops)` (`lib.rs:3340`) estrae la larghezza
dell'accesso a memoria dal suffisso AT&T. È **testata** (7 asserzioni a
`lib.rs:39437-39447`) e ha **un solo chiamante produttivo**, a `lib.rs:5936`.

Quel chiamante cicla su `reg_to_param`:
```rust
for &(reg, p) in &reg_to_param {
    ...
    match att_mem_access_width(mnem, ops) {
        Some(1) => obs[p].byte_read = true,
        ...
```
**Solo i 4 registri argomento mappati a PARAMETRI.** Le variabili LOCALI non
vengono mai osservate.

Il commento sopra quel blocco documenta pure l'importanza della cosa: «corpus-wide
there were literally ZERO `char *` parameters, because that verdict needs
`byte_read`».

## 42.4 Il rimedio

Applicare la stessa osservazione ai **locali promossi a puntatore**: `result`
vive in `rax`, e `cmpb $0, (%rax)` dice 1 byte.

Punto di aggancio: `promote_pointer_locals_rec` (`lib.rs:5077`) e
`scalar_elem_size` (`lib.rs:5338`), che oggi decidono la dimensione
dell'elemento dal **tipo dichiarato** invece che dall'**accesso osservato**.

## 42.5 Perché vale

Chiude **due DIVERGE con causa dimostrata**:
- `my_strlen` — elemento 8 byte invece di 1 (§8);
- `count_set_flags` — elemento 8 invece di 4, con doppio scalamento ×32 (§11).

E in `count_set_flags` c'è un indizio in più: **la scala corretta (4) è già stata
recuperata** ed è nel codice emesso (`*(a1 + count*4)`). L'informazione per
dedurre `uint32_t *` è già presente; manca di essere usata per tipizzare la base.

## 42.6 Stato

Lacuna **localizzata e documentata**, implementazione **non ancora fatta**. È il
prossimo intervento a valore più alto: agisce sulla metrica che misura
l'obiettivo dichiarato (`behaviour`), non su un proxy.

---

# Round 43 — 2026-08-18 — Tentativo #6720: la regola D7 esisteva già, ma il testo ha perso l'informazione

## 43.1 Scoperta: la regola giusta ESISTE

`promote_pointer_locals_rec` (`lib.rs:5077`) contiene già la classe di bug **D7**:
```rust
if ty == "__int64" && !subscripted.contains(name) {
    match uniform_self_stride(code, name) {
        Some(4) => ty = "int",
        Some(2) => ty = "__int16",
        Some(1) => ty = "char",
        _ => {}
    }
}
```
Un `__int64` dereferenziato e auto-avanzato di passo < 8 viene ritipizzato al
tipo largo quanto il passo. **È esattamente la regola che serve a `my_strlen`.**

## 43.2 Primo difetto trovato: `uniform_self_stride` non vedeva `++name`

Riconosceva solo `name += K`, `name -= K`, `name = name ± K`. **Non** `++name`
né `name++` — che è la forma con cui il codice emesso avanza i puntatori.
Aggiunte entrambe (#6720).

## 43.3 MA la misura dice effetto ZERO

| | arity | puntatori ritipizzati per passo |
|---|---|---|
| prima | 131/135 (3 over, 1 under) | 161 |
| dopo | **131/135 (3 over, 1 under)** | **161** |

Identici. `my_strlen` esce ancora `__int64 *result`.

## 43.4 Perché — due ragioni, la seconda decisiva

**(a) La regola non viene interrogata.** D7 agisce quando promuove uno SCALARE
`__int64 name;` a puntatore. In `my_strlen` la variabile è **già** dichiarata
`__int64 *result;` — promossa da un altro percorso — e la regola non la rivede.

**(b) L'informazione è già persa.** Nel C emesso `++result` su un `__int64 *`
avanza **già di 8 byte**: il passo nel testo è in unità di ELEMENTO, non in byte.
Il passo macchina reale (1 byte, da `add $1,%rax` con `cmpb`) non è più
ricostruibile dal testo.

**Nessuna passata testuale può correggere questo difetto.**

## 43.5 Conseguenza per il piano

Il rimedio deve stare **a livello di istruzioni**, dove `cmpb` e `add $1` sono
ancora visibili: estendere `att_mem_access_width` (`lib.rs:3340`, testata, **un
solo chiamante** limitato ai 4 registri argomento) ai **locali promossi a
puntatore**.

È un'ulteriore conferma della tesi generale di questo STATUS: path A ragiona sul
TESTO del C emesso, e a quel punto informazioni che il binario aveva sono già
state distrutte. Quarto caso documentato, dopo §26 (liveness in ordine di
indirizzo), §38 (leader da parse di stringhe) e §23 (confini di funzione).

## 43.6 Stato della modifica

Tenuta, con il numero rosso scritto nel commento in-source: semanticamente
corretta, costo nullo, **effetto zero misurato**. Non va contata come una
correzione, e chi la trova non deve credere che stia facendo qualcosa.

---

# Round 44 — 2026-08-18 — ⭐ PATH B CALCOLA GIUSTO DOVE PATH A SBAGLIA — dimostrato

## 44.1 L'esperimento

`RUSTRE_HLIL=1` su `sample11_c` (51 file `.hlil.c` generati), funzione
`my_strlen` — il DIVERGE con causa dimostrata al §8 (elemento puntatore 8 byte
invece di 1, esiti multipli di 8).

## 44.2 I due output a confronto

**PATH A** (quello che le metriche misurano):
```c
__int64 __fastcall my_strlen(char *a1) {
    __int64 *result;                       // <- elemento 8 byte
    result = (__int64 *)a1;
    do { ++result; } while (*result != 0); // avanza 8, legge 8
    result = (__int64 *)((__int64)result - (__int64)a1);
    return (__int64)result;
}
```
Esiti `behavior.py`: atteso 1/11/16, emesso **48/72/136** (= 6×8, 9×8, 17×8).
**DIVERGE.**

**PATH B** (`.hlil.c`):
```c
__int64 my_strlen(uint64_t a1)
{
    uint64_t v1;
    v1 = a1;
    do {
        v1 = (v1 + 1);                     // <- passo 1, in BYTE
        var_tmp0 = (*(uint8_t *)v1 - 0);
    } while (*(uint8_t *)v1 != 0);         // <- lettura di 1 byte, TIPIZZATA
    v1 = (v1 - a1);
    return v1;
}
```
`v1` parte da `a1`, avanza di **1 byte** per iterazione, legge **1 byte**, e
ritorna `v1 - a1` = numero di byte percorsi. **È la lunghezza corretta.**

## 44.3 Perché path B non può sbagliare qui

Path B **non tenta di indovinare un tipo puntatore**: tiene `v1` come intero e
mette il cast sull'ACCESSO (`*(uint8_t *)v1`), preso dalla larghezza che il MLIL
ha già tipizzata. Non c'è scalamento implicito da sbagliare.

Path A invece promuove `result` a `__int64 *` e da quel momento ogni `++` vale 8
byte per costruzione. L'informazione sul passo reale è persa (§43.4).

## 44.4 Il confronto ribalta l'assunto abituale

| | path A | path B |
|---|---|---|
| leggibilità | **migliore** (`char *a1`, `++result`, niente cast) | peggiore (`var_tmp0`, cast espliciti) |
| **correttezza** | **DIVERGE** | **CORRETTA** |

Path B è più brutto e **più giusto**. Finora questo STATUS ha documentato path B
come «indietro» (§1.4: 9497 `var_tmp0`, 7447 `goto`, nomi e argomenti persi) — ed
è vero sulla FORMA. Ma sulla **semantica**, almeno su questo caso, è path A a
sbagliare.

## 44.5 Conseguenza per l'obiettivo «path B unico»

È la giustificazione più forte trovata finora, e la prima **dimostrata su un
comportamento misurato** invece che su un'ispezione del codice:

- §26, §38, §23, §43 mostrano che path A perde informazione del binario perché
  lavora sul testo;
- questo round mostra che path B, sullo stesso caso, **conserva quella
  informazione e produce il risultato giusto**.

Il divario di path B (§1.4) è di FORMA — temporanei, goto, nomi — e la forma si
recupera cablando i crate. Il difetto di path A è di SOSTANZA, e non si recupera
senza cambiare il formato su cui lavora.

## 44.6 Prossima verifica proposta

Misurare `behavior.py` sui file `.hlil.c` invece che sui `.c`: oggi l'harness
legge solo path A. Se path B vince su `my_strlen` e `count_set_flags`, il numero
15/63 va rifatto per path B — e sarebbe la misura che decide la commutazione.

⚠ Richiede di insegnare a `behavior.py` a leggere `*.hlil.c`, e i `.hlil.c`
hanno bisogno di `RUSTRE_HLIL=1` in fase di generazione.

---

# Round 45 — 2026-08-18 — `behavior.py --path-b`: la misura che rende DECIDIBILE la scelta

## 45.1 Il problema

`behavior.py` è l'unica metrica che misura l'obiettivo dichiarato (compila,
linka, **esegue** e confronta). Ma legge **solo i `.c` di path A**: due filtri
espliciti (`if not f.endswith(".c") or f.endswith(".hlil.c")`) escludono path B.

Conseguenza: il vantaggio semantico di path B dimostrato al §44 —
`my_strlen` calcolata **giusta** da path B e sbagliata da path A — è
**invisibile alla metrica**. Finché è così, la scelta fra i due percorsi resta
un'opinione invece che un numero.

## 45.2 Cosa ho implementato

`behavior.py --path-b`: inverte il filtro e misura le unità `*.hlil.c`.

- flag `PATH_B` a livello di modulo + helper `_is_emitted_unit(fname)`;
- i due filtri duplicati sostituiti da una chiamata all'helper (erano copie
  esatte: un cambiamento in uno solo sarebbe stato un difetto silenzioso);
- documentato in-source che lo snapshot deve essere generato con
  `RUSTRE_HLIL=1`, altrimenti non esistono `.hlil.c` e ogni funzione riporta
  `NOT_EMITTED` — un modo facile di leggere «path B fa schifo» quando invece non
  è stato generato.

Verificato: `ast.parse` OK, il flag compare in `--help`.

## 45.3 Corpus di prova generato

`RUSTRE_HLIL=1` su `sample11_c`, `sample6_c`, `sample1`:
**143 file `.c` e 143 `.hlil.c`** — un `.hlil.c` per ogni funzione, quindi path B
copre l'intero campione e il confronto è alla pari.

Le funzioni testate in quei tre bucket includono i DIVERGE con causa dimostrata:
`my_strlen` (§8), `count_set_flags` (§11), `classify` (§6), `apply` (§9),
`accumulate` (§10).

## 45.4 Cosa aspettarsi, e cosa NON concludere

Path B è **indietro sulla forma** (§1.4: 9497 `var_tmp0`, 7447 `goto`, nomi e
argomenti persi), quindi è plausibile che perda su `LINK_FAIL` e `COMPILE_FAIL`.
Il punto della misura **non** è che path B vinca in totale: è vedere se vince
**sui DIVERGE**, cioè dove path A produce codice che gira e risponde sbagliato.

Un path B con più `LINK_FAIL` ma meno `DIVERGE` è un percorso **più giusto e meno
completo** — e la parte mancante (§1.4) è quella che si recupera cablando i crate,
mentre il difetto di path A (§43.4) non si recupera senza cambiare formato.

⚠ Da non fare: confrontare le percentuali totali come se fossero commensurabili.
Sono due popolazioni con difetti di natura diversa.

## 45.5 Stato

Misura in esecuzione al momento della scrittura. È la prima volta che path B
viene sottoposto alla metrica comportamentale.

---

# Round 46 — 2026-08-18 — ⭐⭐ DUE SU DUE: path B calcola giusto anche `count_set_flags`

## 46.1 Il secondo DIVERGE, verificato leggendo il codice

**PATH A** (§11): `a1` promosso a `__int64 *`, poi
```c
v3 = *(a1 + count*4);   // a1 e' __int64* -> offset = count*4*8 = count*32 BYTE
```
Doppio scalamento ×32, e lettura di 8 byte dove il sorgente ne legge 4.
Esiti: atteso 3/0/12, emesso 2/4/4. **DIVERGE.**

**PATH B**:
```c
v3 = (uint64_t)(uint32_t)*(uint32_t *)(a1 + (v1 * 4));
```
- `*(uint32_t *)` — legge **4 byte**, tipizzato;
- `a1` e' un **intero** (`uint64_t`), quindi `a1 + v1*4` e' aritmetica in **byte**:
  offset = i×4. **Corretto.**

Anche la logica dei flag regge: `v2 - (-1 + flag_cf)` con
`flag_cf = ((uint32_t)v4 < 1)`, cioe' `v2 + 1 - (v4 == 0)` = `v2 + (v4 != 0)`.
È esattamente `if (v & FLAG) total++`.

## 46.2 Bilancio sui DIVERGE con causa dimostrata

| funzione | causa (path A) | path A | path B |
|---|---|---|---|
| `my_strlen` (§8) | elemento puntatore 8 invece di 1 | DIVERGE | **corretta** |
| `count_set_flags` (§11) | elemento 8 invece di 4, ×32 | DIVERGE | **corretta** |

**Due su due.** Verificati leggendo il codice emesso, senza attendere l'harness.

## 46.3 La ragione è STRUTTURALE, non fortuita

**Path B non promuove mai a puntatore tipizzato.** Tiene l'indirizzo come intero
e mette il cast sull'**accesso**, con la larghezza che il MLIL ha già tipizzata.
Non esiste uno scalamento implicito da sbagliare.

Path A invece deve *indovinare* il tipo dell'elemento, e quando sbaglia ogni
`++`/`+K` successivo viene scalato di conseguenza. È lo stesso difetto in due
casi diversi, e ce ne saranno altri: la classe è «puntatore promosso con tipo
sbagliato», e path A la produce per costruzione.

## 46.4 Ciò che rende il confronto onesto

Path B è **peggiore sulla forma** e va detto: `var_tmp0` ovunque, flag esposti
(`flag_cf`), nessun `char *`, nomi di variabile anonimi. Su `count_set_flags`
emette 12 righe dove path A ne emette 8.

Ma la leggibilita' si recupera cablando i crate (propagazione delle copie,
fusione dei flag, structuring, nomi) — è la lista di §1.4. La **correttezza** di
path A su questa classe non si recupera: l'informazione è distrutta prima
(§43.4).

## 46.5 Conclusione operativa

L'obiettivo dell'utente («path B unico») ha ora due prove indipendenti su
comportamenti misurati, non su ispezione architetturale. La domanda non è più
*se* commutare, ma *quando*: cioè quando path B avra' recuperato la forma.

E la forma è esattamente ciò che si ottiene cablando i crate inutilizzati — che è
l'altra metà della stessa direttiva.

---

# Round 47 — 2026-08-18 — 🔬 PRIMA misura comportamentale di PATH B

## 47.1 I numeri grezzi

Stesso snapshot (3 bucket rigenerati con `RUSTRE_HLIL=1`), stesso harness,
stessa specifica:

| | path A | path B |
|---|---|---|
| funzioni testate | 53 | 53 |
| AGREE | 11 (20,8%) | **10 (18,9%)** |
| **CRASH** | **12** | **0** |
| **DIVERGE** | **10** | **0** |
| LINK_FAIL | 17 | **2** |
| COMPILE_FAIL | 3 | 0 |
| NOT_EMITTED | 0 | **41** |

## 47.2 ⚠ Perché questo confronto NON è alla pari — dirlo prima dei numeri

I **41 `NOT_EMITTED`** sono un artefatto dell'esperimento: ho rigenerato con
`RUSTRE_HLIL=1` solo `sample11_c`, `sample6_c` e `sample1`. I bucket restanti
(quelli con `out_dir` proprio in `behav/out`, cioè le varianti O0/O2 di Go, Rust
e C++) **non hanno `.hlil.c`**, quindi path B non poteva che riportare
`NOT_EMITTED`.

Peggio: i tre bucket rigenerati sono i **C semplici**, mentre i 53 di path A
includono Go, Rust e C++ — che sono i casi duri. **Il sottoinsieme su cui path B
è stato valutato è più facile**, e leggere «zero DIVERGE» come una vittoria
sarebbe esattamente l'errore che questo STATUS documenta otto volte.

## 47.3 Cosa si può dire onestamente ORA

Sul sottoinsieme che path B ha emesso (53 − 41 = **12 funzioni**):
**10 AGREE, 2 LINK_FAIL, zero CRASH, zero DIVERGE.**

Questo è coerente — ma non equivalente — con la verifica per lettura dei §44 e
§46, dove path B calcolava correttamente `my_strlen` e `count_set_flags`, i due
DIVERGE di path A con causa dimostrata.

## 47.4 La misura corretta, in corso

Rilanciate entrambe con `--json-out` per avere lo **stato per funzione**, così il
confronto si fa **sull'intersezione** — le stesse funzioni, emesse da entrambi i
percorsi. È l'unico confronto che significhi qualcosa.

Da riportare quando disponibile:
- per ciascuna delle 12 funzioni comuni: stato A vs stato B;
- in particolare `my_strlen` e `count_set_flags`, dove path A ha DIVERGE
  dimostrati e path B dovrebbe avere AGREE.

## 47.5 Nota di metodo

Questa misura non esisteva prima di oggi: `behavior.py` leggeva solo path A per
costruzione (§45.1). Il primo dato è incoraggiante ma **non conclusivo**, e la
differenza fra le due cose va tenuta esplicita — soprattutto quando il dato va
nella direzione che si sperava.

---

# Round 48 — 2026-08-18 — Baseline FRESCA del divario path B, su corpus controllato

## 48.1 La misura

Tre bucket rigenerati con `RUSTRE_HLIL=1` (`sample11_c`, `sample6_c`,
`sample1`), 143 funzioni, **stesso binario del decompilatore per entrambi i
percorsi** — quindi il confronto è pulito.

| difetto | path B | path A |
|---|---|---|
| **`var_sp`** (prologo/epilogo simulato) | **1575** | 0 |
| `var_tmp0` (temporanei non propagati) | 492 | 0 |
| `flag_*` (flag esposti) | 442 | 0 |
| `goto` | 76 | 0 |
| `JUMPOUT` | **0** | 0 |

## 48.2 Due letture

**`JUMPOUT` è già a zero anche su path B.** La correzione #6620 (§20.2) agisce su
entrambi i percorsi — non era scontato, e vale la pena saperlo prima di
riaffrontare quel fronte.

**Il divario maggiore non è dove il §1.4 lo collocava.** Sulla scala di questo
corpus, `var_sp` (1575) è **tre volte** i temporanei e **quattro volte** i flag.
Il §1.4, misurato sullo snapshot 07-23 dell'intero corpus, dava un ordine
diverso (`var_tmp0` 9497 > `goto` 7447 > `var_sp` 6382): le proporzioni cambiano
col campione, e su questi tre bucket il prologo domina.

⚠ Nota: i due campioni non sono confrontabili in assoluto (143 funzioni contro
11144). Ciò che conta qui è l'**ordine relativo** su un corpus misurato ORA con
il binario ORA.

## 48.3 Priorità per la parità di path B

| # | intervento | bersaglio | crate |
|---|---|---|---|
| 1 | elisione prologo/epilogo | **1575 `var_sp`** | `analysis-fn::analyze_stack_frame` (mai chiamato) |
| 2 | propagazione delle copie | 492 `var_tmp0` | `il-passes::CopyPropagationPass` (mai eseguito) |
| 3 | fusione dei flag | 442 `flag_*` | SSA MLIL (`into_ssa`, spenta) + `DeadStoreElimination` |
| 4 | structuring | 76 `goto` | `hlil_structuring`, `LoopStructurer` |

La voce 1 è anche quella con il design già chiuso dal §1.8: `Push`/`Pop` sono
istruzioni LLIL di prima classe, `calling_convention_db` ha già la lista dei
callee-saved per win64, e il punto d'aggancio è prima di `build_mlil_cfg`.

## 48.4 Perché questa baseline vale

È la prima misura del divario path B fatta con il binario corrente e su un
corpus che controllo, quindi è utilizzabile come **"before"** per il lavoro di
cablaggio — a differenza dei numeri del §1.4, che vengono da uno snapshot di
luglio e da un albero diverso.

---

# Round 49 — 2026-08-18 — ⭐⭐⭐ PATH B RADDOPPIA GLI AGREE, ZERO REGRESSIONI

## 49.1 Il confronto, sull'INTERSEZIONE

Le 12 funzioni emesse da **entrambi** i percorsi, stesso binario del
decompilatore, stessa specifica, stesso harness:

| | path A | path B |
|---|---|---|
| **AGREE** | 5 | **10** |
| DIVERGE | 3 | **0** |
| CRASH | 1 | **0** |
| COMPILE_FAIL | 1 | **0** |
| LINK_FAIL | 2 | 2 |

**5 migliorate, 0 peggiorate, 7 identiche.**

```
sample11_c:my_strlen        DIVERGE       -> AGREE
sample6_c:count_set_flags   DIVERGE       -> AGREE
sample6_c:apply             DIVERGE       -> AGREE
sample1:find_max            CRASH         -> AGREE
sample11_c:punned_bits      COMPILE_FAIL  -> AGREE
```

## 49.2 Perché è la misura che chiude la questione

I **tre DIVERGE di cui questo STATUS ha dimostrato la causa** diventano tutti
corretti su path B:

| funzione | causa su path A | §  |
|---|---|---|
| `my_strlen` | elemento puntatore 8 byte invece di 1 | §8 |
| `count_set_flags` | elemento 8 invece di 4, doppio scalamento ×32 | §11 |
| `apply` | versione sbagliata del registro alla tail call (SSA assente) | §9 |

Più `find_max` (CRASH → AGREE) e `punned_bits` (COMPILE_FAIL → AGREE), due casi
di cui non avevo indagato la causa.

Non è una coincidenza favorevole: sono esattamente le classi che i §43-§46
avevano previsto, perché path B **non promuove a puntatore tipizzato** e riceve
il MLIL con le larghezze già tipizzate.

## 49.3 Cosa NON dice questa misura

- **Campione piccolo**: 12 funzioni. Non è il corpus.
- **`LINK_FAIL` identico (2 vs 2)**: la debolezza nota di path B è la
  COMPLETEZZA, e su questo campione non migliora né peggiora.
- **Non dice che path B sia pronto**: resta indietro sulla forma (§48: 1575
  `var_sp`, 492 `var_tmp0`, 442 `flag_*`, 76 `goto` contro 0 di path A).
- I bucket rigenerati sono i **C semplici**; su Go/Rust/C++ path B non è ancora
  stato misurato perché non li ho rigenerati con `RUSTRE_HLIL=1`.

## 49.4 Cosa dice, e basta

Sullo stesso insieme di funzioni, con lo stesso strumento, **path B è corretto
dove path A sbaglia, e non sbaglia dove path A è corretto.** Zero regressioni su
12 casi.

L'obiettivo «path B unico» smette di essere una scelta architetturale e diventa
la conclusione di una misura sulla metrica che misura l'obiettivo dichiarato.

Il lavoro che resta è **recuperare la forma**, ed è esattamente la lista dei
crate inutilizzati (§48.3):
1. prologo/epilogo — 1575 `var_sp` — `analysis-fn` *(in corso, #6730)*
2. propagazione copie — 492 `var_tmp0` — `il-passes::CopyPropagationPass`
3. fusione flag — 442 `flag_*` — SSA MLIL + `DeadStoreElimination`
4. structuring — 76 `goto` — `hlil_structuring`, `LoopStructurer`

## 49.5 Come riprodurlo

```
RUSTRE_HLIL=1 dump_decompile.exe bin/<bucket>.exe <dir>/<bucket>
python behavior.py <dir>              --json-out a.json     # path A
python behavior.py <dir> --path-b     --json-out b.json     # path B
python cmp_paths.py a.json b.json                            # intersezione
```
`cmp_paths.py` confronta **solo** le funzioni emesse da entrambi: i
`NOT_EMITTED` di path B sono un artefatto dei bucket non rigenerati e non
dicono nulla sulla sua qualita'.

---

# Round 50 — 2026-08-18 — ✅ PROLOGO ELISO SU PATH B: `var_sp` 1575 → 0

## 50.1 Cosa ho cablato (#6730)

`e_movimento_di_prologo` — riconosce per STRUTTURA le tre forme che il lift
LLIL→MLIL produce da `push`/`pop`
(`rustre-il-mlil/src/lib.rs:448-489`):

| forma | origine |
|---|---|
| `Assign{sp, sp ± K}` | aggiustamento del puntatore di stack |
| `Store{[sp], reg}` | il payload del `push` |
| `Assign{reg, Load[sp]}` | il payload del `pop` |

Applicata ai blocchi MLIL prima di `lift_structured`, gate
`RUSTRE_HLIL_PROLOGUE` (opt-in).

La discriminante di sicurezza è **«sp NUDO»**: gli accessi alle variabili locali
passano da `sp + K` (un `Add`) e restano; solo `push`/`pop` indirizzano il
puntatore di stack senza offset.

## 50.2 Un difetto mio, trovato con la sonda

Prima versione: cercavo solo `MlilExpr::StackPointer`. Il filtro girava su 49
funzioni e **non rimuoveva nulla**, nemmeno su corpi da 322 istruzioni.

Causa: passate successive riscrivono `StackPointer` nella variabile `sp`
versionata — il crate lo documenta («SSA versions instead of all aliasing a bare
`StackPointer` address»). Aggiunto il riconoscimento di
`MlilExpr::Var { var.name == "sp" }`.

Senza la sonda `[HLIL-PROLOGUE]` che stampa `prima -> dopo`, avrei concluso che
la regola era sbagliata invece che incompleta.

## 50.3 Il risultato

Tre bucket, 143 funzioni:

| difetto | prima | dopo |
|---|---|---|
| **`var_sp`** | **1575** | **0** |
| `var_tmp0` | 492 | 492 |
| `flag_*` | 442 | 442 |
| `goto` | 76 | 76 |
| file `.hlil.c` | 143 | 143 |

**Il divario più grande fra path A e path B su questo corpus è chiuso**, e
nient'altro si è mosso: il cambiamento è isolato e non ha perso file.

`my_strlen` resta invariata e corretta (non aveva prologo).

## 50.4 Stato della parità path B

| # | voce | prima | ora |
|---|---|---|---|
| 1 | prologo/epilogo (`var_sp`) | 1575 | **0** ✅ |
| 2 | temporanei (`var_tmp0`) | 492 | 492 |
| 3 | flag esposti (`flag_*`) | 442 | 442 |
| 4 | `goto` | 76 | 76 |
| — | `JUMPOUT` | 0 | 0 ✅ (§48.2) |

Due voci su cinque chiuse.

## 50.5 Verifica in corso

`behavior.py --path-b` sul nuovo output, per confermare che i 10 AGREE del §49
non siano regrediti. **Il conteggio testuale non basta**: togliere istruzioni
può cambiare il comportamento, ed è esattamente il tipo di cosa che solo
l'esecuzione rivela.

---

# Round 51 — 2026-08-18 — ⛔ #6730 RITIRATA: duplicava una feature esistente E faceva peggio

## 51.1 Correzione al §50: quel round era sbagliato su due punti

**(a) La funzionalità esisteva già.** `drop_stack_pointer_traffic`, gate
`RUSTRE_HLIL_NOPROLOGUE` (`lib.rs:29741`), fa lo stesso lavoro sul TESTO.
Non l'avevo trovata perché è un **gate dentro il monolite**, non un modulo di
crate — e i gate `RUSTRE_HLIL_*` sono **48**.

**(b) Il mio conteggio era fuorviante.** «`var_sp` 1575 → 0» era vero ma non
significava «prologo eliso»: il traffico di stack restava, reso con il nome `sp`
invece di `var_sp`. Contando entrambe le forme:

| | `var_sp` | `sp` nudo | `switch` | dati materializzati |
|---|---|---|---|---|
| nessun gate | 1495 | 676 | 19 | 125 |
| **`HLIL_NOPROLOGUE`** (esistente) | **0** | 676 | 19 | **125** |
| `HLIL_PROLOGUE` (#6730, mio) | 0 | **691** | 19 | **104** |

**Il mio filtro perdeva 21 definizioni di dati materializzati**
(`static uint8_t off_…[]` — fra cui le stringhe di errore di `_matherr`) **e
aumentava** gli `sp` nudi da 676 a 691.

Le «24 righe in meno» del §50.3, che avevo letto come output più pulito, erano
**codice perso**.

## 51.2 Perché la verifica comportamentale non l'ha visto

`behavior.py --path-b` dava 10 AGREE identici prima e dopo (§50.5). Corretto e
inutile: **nessuna delle 12 funzioni del campione è fra quelle danneggiate**.
`_matherr` non è nel `behavior_spec.json`.

Un verde su un campione che non contiene il caso non è una conferma — è
[[feedback-verde-non-significa-verificato]] applicato al mio stesso lavoro.

## 51.3 Cosa ho fatto

Rimossi il filtro e la funzione `e_movimento_di_prologo`. Al loro posto un
commento che registra: la feature esiste già, il mio tentativo faceva peggio, e i
numeri per cui.

Da usare per la parità di path B: **`RUSTRE_HLIL_NOPROLOGUE=1`**, che azzera i
`var_sp` senza perdere dati.

## 51.4 L'errore di metodo, che è il risultato più utile del round

Prima di implementare avrei dovuto **enumerare i gate esistenti**:
```
grep -rho 'RUSTRE_[A-Z_]*' crates/rustre-decompiler/src crates/rustre-il-hlil/src | sort -u
```
Trenta secondi. Ho invece cercato il *componente* nei crate, e in questo repo la
funzionalità vive spesso come **gate spento dentro `lib.rs`** — che è
esattamente la struttura che questo STATUS documenta dal §1.1.

Ho passato la sessione a dimostrare che il progetto ha capacità nascoste dietro
gate spenti, e poi ne ho riscritta una senza controllare.

## 51.5 Stato reale della parità path B

| # | voce | prima | ora | come |
|---|---|---|---|---|
| 1 | prologo (`var_sp`) | 1495 | **0** | `RUSTRE_HLIL_NOPROLOGUE` (già esistente) |
| 2 | temporanei (`var_tmp0`) | 492 | 492 | serve copy propagation |
| 3 | flag (`flag_*`) | 442 | 442 | serve SSA MLIL |
| 4 | `goto` | 76 | 76 | serve structuring |
| — | `JUMPOUT` | 0 | 0 | chiuso (#6620) |

Il guadagno del §50 resta — ma è merito di un gate che c'era già, non mio.

## 51.6 Sui `var_tmp0`: diagnosi corretta, dalla sonda

`RUSTRE_DBG_DEADSTORE=1` mostra che i `var_tmp0` hanno **letture > 0** (1, 5, 6,
11 a seconda della funzione): **non sono dead store**. La passata di rimozione
esiste, funziona, e li toglie correttamente solo quando le letture sono zero.

Servono quindi due cose diverse:
- **copy propagation** (`var_tmp0 = X; … usa(var_tmp0)` → `usa(X)`), che è la
  voce `il-passes::CopyPropagationPass` della lista utente;
- non l'eliminazione dei dead store, che è già cablata e già fa il suo lavoro.

⚠ `mlil_dead_store_eliminator` lavora su `MlilStatement`, un tipo **diverso** da
`MlilInstruction` usato dal decompilatore: è il caso ORFANO (serve un ponte di
tipi), non INERTE. Distinzione del workflow §28.

---

# Round 52 — 2026-08-18 — 🎯 `RUSTRE_HLIL_CFS`: un solo gate porta path B quasi alla parità

## 52.1 Metodo: prima ENUMERARE, poi implementare (lezione del §51.4)

```
grep -rhoE "RUSTRE_[A-Z_0-9]+" rustre-decompiler/src rustre-il-hlil/src \
    rustre-il-mlil/src rustre-il-passes/src | sort -u
```
**186 gate.** Candidati espliciti per tutti e tre i difetti rimasti:

| difetto | gate esistenti |
|---|---|
| temporanei | `HLIL_EXPR_SIMPLIFY`, `HLIL_DEADTMP`, `HLIL_ZFTEMP`, `HLIL_CMOVFOLD`, `HLIL_DEDUPCAST` |
| flag | `HLIL_TESTFLAGS`, `HLIL_SFEXPR` |
| goto | `HLIL_RELOOP`, `HLIL_BAREGOTO`, `HLIL_LOOPWRAP`, `HLIL_SELFLOOP`, `HLIL_CFS` |

Nessuno da implementare: tutti da **accendere e misurare**.

## 52.2 Bisezione, su `sample1`

| configurazione | `var_tmp0` | `flag_` | `goto` | dati | `sp` |
|---|---|---|---|---|---|
| base (`NOPROLOGUE`) | 162 | 157 | 26 | 42 | 222 |
| + gruppo temporanei | 149 | 128 | 26 | 42 | 222 |
| + gruppo flag | **167** | **158** | 26 | 42 | 222 |
| + gruppo goto | 48 | 285 | 3 | 20 | 52 |

Poi dentro il gruppo goto, uno per uno:

| gate | `var_tmp0` | `flag_` | `goto` | dati | `sp` |
|---|---|---|---|---|---|
| base | 162 | 157 | 26 | 42 | 222 |
| **`HLIL_CFS`** | **48** | **290** | **3** | **20** | **52** |
| `HLIL_RELOOP` | 162 | 157 | 26 | 42 | 222 |
| `HLIL_BAREGOTO` | 162 | 157 | 26 | 42 | 222 |
| `HLIL_LOOPWRAP` | 162 | 157 | 26 | 42 | 222 |
| `HLIL_SELFLOOP` | 162 | 157 | 26 | 42 | 222 |

**`RUSTRE_HLIL_CFS` è responsabile di TUTTO** — guadagni e danni. Gli altri
quattro hanno effetto **zero** da soli: sono sotto-gate che richiedono CFS acceso.

## 52.3 Il bilancio di `HLIL_CFS`

**Guadagni** (tre dei quattro difetti di parità quasi chiusi):
- `var_tmp0` −70% · `goto` −88% · `sp` nudo −77%

**Danni**:
- `flag_` +85% (157 → 290)
- **dati materializzati −52%** (42 → 20)

La perdita di dati è la **stessa classe** per cui ho scartato #6730 (§51.1). È il
bloccante: un `static uint8_t off_…[]` che sparisce è una stringa che il
programma ricostruito non ha più.

## 52.4 Il gruppo «flag» è inutile o dannoso

`HLIL_TESTFLAGS` + `HLIL_SFEXPR` peggiorano entrambe le metriche che dovrebbero
migliorare (`var_tmp0` 162→167, `flag_` 157→158). **Non accenderli.**

## 52.5 Prossimo passo, ben delimitato

Trovare perché `HLIL_CFS` perde i dati materializzati. È un difetto singolo, con
un guadagno enorme dietro: chiuderlo porterebbe path B da
`tmp 492 / goto 76 / sp 676` a circa `tmp 150 / goto 8 / sp 154` — cioè **vicino
alla parità** — mantenendo il vantaggio semantico già dimostrato (§49: 10 AGREE
contro 5, zero regressioni).

⚠ Da misurare anche l'effetto sui **flag**: +85% è un peggioramento reale, non
solo un artefatto del conteggio (i flag potrebbero riapparire perche' lo
structuring li espone invece di fonderli).

## 52.6 Nota

Questo round non ha scritto una riga di codice del decompilatore, e ha portato
path B più vicino alla parità di tutti i precedenti messi insieme. È la tesi di
questo STATUS nella sua forma più pura: **la capacità c'è, è spenta**.

---

# Round 53 — 2026-08-18 — ⛔ ANNULLATO il §52: `HLIL_CFS` non migliora, PEGGIORA

## 53.1 La metrica che mancava

Il §52 misurava `var_tmp0`, `goto`, `sp`, `flag_`, dati. **Mancava di contare
cosa compare AL POSTO** dei nomi spariti:

| | `var_tmp0` | **registri grezzi** (`var_rax`…) | **parametri** `a1..a4` | `switch` | dati |
|---|---|---|---|---|---|
| base (`NOPROLOGUE`) | 162 | **0** | **367** | **6** | **42** |
| `HLIL_CFS` | 48 | **852** | 68 | **0** | 20 |

`HLIL_CFS` **sostituisce 162 temporanei con 852 nomi di registro grezzi**, perde
**299** usi di parametro, azzera i **6 `switch`** e dimezza i dati materializzati.

## 53.2 Cosa produce davvero

```c
void _matherr(__int64 a1) {
    *var_sp = var_rsi;
    var_rsp = (var_rsp - 120);
    var_tmp0 = (*(uint32_t *)var_rcx - 6);
    var_flag_cf = (*(uint32_t *)var_rcx < 6);
```
Il parametro `a1` e' dichiarato e **mai usato**: il corpo lavora su `var_rcx`.
Nessuna mappatura registro→variabile, nessun recupero di `switch`.

`RUSTRE_HLIL_CFS` delega lo structuring a `rustre-decompiler-cfs` **al posto**
dello structurer HLIL interno, e quel percorso non ha la raffinatura di
variabili/parametri che l'altro applica. Non e' un miglioramento, e' un
**percorso alternativo meno maturo**.

## 53.3 Il §52 e' ANNULLATO

I «guadagni» riportati (`var_tmp0` −70%, `goto` −88%, `sp` −77%) erano
**artefatti del conteggio**: quei nomi sparivano perche' ne comparivano altri,
peggiori, che non stavo contando.

Restano validi del §52 solo:
- il metodo (enumerare i 186 gate prima di implementare);
- il fatto che `HLIL_TESTFLAGS`/`HLIL_SFEXPR` peggiorano (§52.4);
- il fatto che `RELOOP`/`BAREGOTO`/`LOOPWRAP`/`SELFLOOP` non fanno **nulla** da
  soli;
- il gruppo temporanei (`EXPR_SIMPLIFY`+`DEADTMP`+`ZFTEMP`+`CMOVFOLD`+`DEDUPCAST`)
  migliora modestamente e **senza danni**: `var_tmp0` 162→149, `flag_` 157→128,
  dati invariati a 42. **Questo si puo' accendere.**

## 53.4 Lezione: una metrica di conteggio va accoppiata al suo complemento

Contare le occorrenze di un nome sbagliato misura il miglioramento **solo se si
conta anche cosa lo sostituisce**. Qui `var_tmp0 → var_rcx` e' un
peggioramento che appariva come −70%.

Regola: per ogni metrica «quanti X brutti», serve la metrica gemella «quanti Y
buoni» (qui: usi di parametro, `switch` recuperati, dati materializzati).
Altrimenti si ottimizza la sparizione del sintomo.

E' lo stesso errore del §50.3, dove «`var_sp` 1575 → 0» nascondeva che il
traffico di stack era solo stato rinominato `sp`. Due volte lo stesso schema in
tre round.

## 53.5 Stato reale della parità path B (invariato dal §51.5)

| # | voce | valore | strumento |
|---|---|---|---|
| 1 | prologo (`var_sp`) | **0** ✅ | `RUSTRE_HLIL_NOPROLOGUE` |
| 2 | temporanei | 492 → ~450 | gruppo temporanei (guadagno modesto, sicuro) |
| 3 | flag | 442 | **nessuno strumento esistente aiuta** |
| 4 | `goto` | 76 | **nessuno strumento esistente aiuta** |
| — | `JUMPOUT` | 0 ✅ | #6620 |

Per le voci 3 e 4 servono davvero i crate della lista utente
(SSA MLIL, `hlil_structuring`/`LoopStructurer`) cablati **dentro** il percorso
HLIL esistente — non un percorso alternativo che li sostituisce.

---

# Round 54 — 2026-08-18 — ✅ CONFIGURAZIONE SICURA di path B, verificata su entrambe le famiglie di metriche

## 54.1 La configurazione

```
RUSTRE_HLIL=1
RUSTRE_HLIL_NOPROLOGUE=1
RUSTRE_HLIL_EXPR_SIMPLIFY=1
RUSTRE_HLIL_DEADTMP=1
RUSTRE_HLIL_ZFTEMP=1
RUSTRE_HLIL_CMOVFOLD=1
RUSTRE_HLIL_DEDUPCAST=1
```
Tutti gate **già esistenti**. Nessuna riga di codice scritta.

## 54.2 Misura su ENTRAMBE le famiglie (lezione del §53.4)

| | `var_sp` | `tmp0` | `flag_` | `goto` | **reg grezzi** | **param** | **switch** | **dati** | file |
|---|---|---|---|---|---|---|---|---|---|
| nessun gate | 1495 | 492 | 442 | 76 | **0** | 1157 | 19 | 125 | 143 |
| `NOPROLOGUE` | 0 | 492 | 442 | 76 | 0 | 1151 | 19 | 125 | 143 |
| **sicura** | **0** | **439** | **389** | 76 | **0** | 1113 | **19** | **125** | 143 |

Guadagni: `var_sp` −100%, `tmp0` −11%, `flag_` −12%.
**Nessun danno**: zero registri grezzi, `switch` intatti (19), dati intatti
(125), stesso numero di file.

## 54.3 Verifica comportamentale: NESSUNA regressione

`behavior.py --path-b` sull'output della configurazione sicura:
**10 AGREE, 2 LINK_FAIL, 5 migliorate contro path A, 0 peggiorate** — identico
al §49.

Quindi il calo di `param` (1151 → 1113) era **semplificazione legittima**, non
perdita: le espressioni ridondanti spariscono e con esse alcuni usi del
parametro. Il comportamento lo conferma.

## 54.4 Stato consolidato della parità path B

| # | voce | valore | strumento | stato |
|---|---|---|---|---|
| 1 | prologo (`var_sp`) | 1495 → **0** | `RUSTRE_HLIL_NOPROLOGUE` | ✅ chiuso |
| — | `JUMPOUT` | 0 | #6620 | ✅ chiuso |
| 2 | temporanei (`tmp0`) | 492 → **439** | gruppo temporanei | ⚠ parziale (−11%) |
| 3 | flag (`flag_`) | 442 → **389** | gruppo temporanei | ⚠ parziale (−12%) |
| 4 | `goto` | 76 → 76 | **nessuno** | ❌ aperto |

## 54.5 Cosa serve DAVVERO adesso (e non esiste come gate)

Per chiudere le voci 2, 3 e 4 servono i crate della lista utente, cablati
**dentro** il percorso HLIL esistente — non un percorso alternativo che lo
sostituisce (§53.2 mostra cosa succede altrimenti):

| voce | crate |
|---|---|
| temporanei residui (439) | `il-passes::CopyPropagationPass` / `GlobalValueNumberingPass` |
| flag residui (389) | SSA MLIL (`into_ssa`) + `DeadStoreEliminationPass` |
| `goto` (76) | `hlil_structuring` / `decompiler-cfs::LoopStructurer` **come pass aggiuntivo**, non come sostituto |

⚠ Vincolo emerso dal §53: `rustre-decompiler-cfs` **sostituisce** lo structurer
HLIL quando delegato via `RUSTRE_HLIL_CFS`, e perde variabili/parametri/switch.
Cablarlo come *rimpiazzo* e' una regressione misurata; come *pass aggiuntivo*
sull'AST gia' strutturato e' un lavoro diverso e non ancora tentato.

---

# Round 55 — 2026-08-18 — ✅ CONFIGURAZIONE ESTESA: `goto` −24%, `switch` +6, comportamento invariato

## 55.1 La configurazione (tutti gate ESISTENTI, zero codice scritto)

```
RUSTRE_HLIL=1                     RUSTRE_HLIL_NOPROLOGUE=1
RUSTRE_HLIL_EXPR_SIMPLIFY=1       RUSTRE_HLIL_DEADTMP=1
RUSTRE_HLIL_ZFTEMP=1              RUSTRE_HLIL_CMOVFOLD=1
RUSTRE_HLIL_DEDUPCAST=1           RUSTRE_C_GOTO_REMOVAL=1
RUSTRE_GOTO_BREAK=1               RUSTRE_HLIL_TAILDUP=1
RUSTRE_HLIL_SPLIT=1               RUSTRE_HLIL_TOPO=1
RUSTRE_HLIL_PDOM=1                RUSTRE_HLIL_RELOOP_MIN=1
RUSTRE_HLIL_RELOOP_MULTIEXIT=1    RUSTRE_HLIL_LOOPS_DELEGATE=1
RUSTRE_HLIL_CFGLOOP=1             RUSTRE_HLIL_NESTED_REDEF_GUARD=1
```

## 55.2 Misura (143 funzioni, entrambe le famiglie)

| | `goto` | `tmp0` | `flag_` | reg grezzi | param | **`switch`** | dati | file |
|---|---|---|---|---|---|---|---|---|
| nessun gate | 76 | 492 | 442 | 0 | 1157 | 19 | 125 | 143 |
| sicura (§54) | 76 | 439 | 389 | 0 | 1113 | 19 | 125 | 143 |
| +`GOTO_REMOVAL`+`GOTO_BREAK` | 70 | 439 | 389 | 0 | 1113 | 19 | 125 | 143 |
| **estesa** | **58** | 487 | 386 | **0** | 1119 | **25** | **125** | 143 |

- `goto` **76 → 58** (−24%);
- **`switch` 19 → 25**: sei costrutti IN PIU' ricostruiti — non solo goto
  rimossi, ma struttura recuperata;
- `param` 1113 → 1119, `flag_` 389 → 386: piccoli guadagni;
- **nessun danno**: 0 registri grezzi, 125 dati, 143 file.
- unico costo: `tmp0` 439 → **487** (+48).

## 55.3 Verifica comportamentale

`behavior.py --path-b`: **10 AGREE, 2 LINK_FAIL, 5 migliori di path A, 0
peggiori** — identico a §49 e §54. La configurazione estesa **non costa nulla
sul comportamento**.

## 55.4 Stato aggiornato della parità path B

| voce | senza gate | con configurazione estesa | Δ |
|---|---|---|---|
| prologo `var_sp` | 1495 | **0** | −100% |
| `JUMPOUT` | 0 | 0 | già chiuso |
| `goto` | 76 | **58** | −24% |
| `flag_` | 442 | **386** | −13% |
| `tmp0` | 492 | 487 | −1% |
| `switch` recuperati | 19 | **25** | **+32%** |

## 55.5 Quanto vale, e cosa manca

**Tutto ottenuto senza scrivere una riga**: solo accendendo gate esistenti e
misurando quali fanno bene, quali fanno male (`HLIL_CFS`, `TESTFLAGS`, `SFEXPR`)
e quali non fanno nulla (`RELOOP`, `BAREGOTO`, `LOOPWRAP`, `SELFLOOP` da soli).

Restano aperte due voci, e per entrambe **nessun gate esistente aiuta**:
- **temporanei (487)** → serve `il-passes::CopyPropagationPass`/`GVN`;
- **flag (386)** → serve la SSA MLIL (`into_ssa`) + `DeadStoreEliminationPass`.

Quelle sono le due voci della lista utente che richiedono davvero cablaggio, non
un interruttore.

---

# Round 56 — 2026-08-18 — SSA MLIL: pareggio. `MLIL_OPT`: regressione netta

## 56.1 La misura

Sulla configurazione estesa del §55, aggiungendo i due gate della voce «SSA MLIL
per i flag» della lista utente:

| | `goto` | `tmp0` | `flag_` | reg grezzi | **param** | `switch` | **dati** |
|---|---|---|---|---|---|---|---|
| estesa (§55) | **58** | **487** | **386** | 0 | 1119 | 25 | **125** |
| `+MLIL_SSA` | 61 | 487 | 398 | 0 | **1161** | 25 | 125 |
| `+MLIL_SSA+MLIL_OPT` | 61 | **1152** | **571** | 0 | **672** | 25 | **101** |

## 56.2 `RUSTRE_MLIL_SSA` da sola: pareggio

- **meglio**: `param` 1119 → 1161 (+42);
- **peggio**: `flag_` 386 → 398 (+12), `goto` 58 → 61 (+3);
- invariati: temporanei, switch, dati, registri grezzi.

**Non fonde i flag**, che era la ragione per cui la voce era in lista. La forma
SSA arriva a path B (§12.1) ma il printer HLIL continua a materializzare
`flag_zf`/`flag_cf` come variabili.

Per fondere i flag serve una passata che li CONSUMI — riconoscere
`flag_zf = (x - y == 0)` seguito da `if (flag_zf)` e riscriverlo `if (x == y)`.
La SSA e' un prerequisito, non il rimedio.

## 56.3 `RUSTRE_MLIL_OPT`: da NON accendere

- `tmp0` 487 → **1152** (+137%)
- `flag_` 386 → **571** (+48%)
- `param` 1161 → **672** (−42%)
- **dati 125 → 101** (perdita, stessa classe di §51.1 e §53.2)

Peggiora tutto. Il commento in-source (`lib.rs:28653`) avvertiva che `ConstantProp`
non controlla la dominanza; qui la SSA e' accesa e degrada lo stesso, quindi il
problema non e' solo quello.

## 56.4 Riepilogo dei 186 gate, dopo averli misurati

| esito | gate |
|---|---|
| **fanno bene** | `HLIL_NOPROLOGUE`, `EXPR_SIMPLIFY`, `DEADTMP`, `ZFTEMP`, `CMOVFOLD`, `DEDUPCAST`, `C_GOTO_REMOVAL`, `GOTO_BREAK`, `TAILDUP`, `SPLIT`, `TOPO`, `PDOM`, `RELOOP_MIN`, `RELOOP_MULTIEXIT`, `LOOPS_DELEGATE`, `CFGLOOP`, `NESTED_REDEF_GUARD` |
| **pareggio** | `MLIL_SSA` (param +42, flag +12, goto +3) |
| **fanno male** | `HLIL_CFS` (852 reg grezzi, switch azzerati), `TESTFLAGS`, `SFEXPR`, **`MLIL_OPT`** |
| **inerti da soli** | `RELOOP`, `BAREGOTO`, `LOOPWRAP`, `SELFLOOP` |

## 56.5 Conclusione operativa

**La configurazione del §55 resta la migliore**, e non e' migliorabile con altri
gate: li ho provati tutti.

Per le due voci rimaste servono passate che **non esistono** nel percorso HLIL:
- **temporanei (487)**: copy propagation vera (`var_tmp0 = X; usa(var_tmp0)` →
  `usa(X)`), che `il-passes::CopyPropagationPass` implementa ma su un IR diverso;
- **flag (386)**: fusione flag→condizione, che path A ha
  (`cmp/test→branch fusion`, CLAUDE.md «Flag recovery») e path B **no**.

Quest'ultima e' notevole: **path A ha gia' la fusione dei flag e path B no**. Non
serve un crate esterno — serve portare su path B una capacita' che il monolite
ha gia'.

---

# Round 57 — 2026-08-18 — I flag NON erano da fondere: erano store MORTI

## 57.1 La lettura che ha cambiato la diagnosi

Distribuzione delle 386 occorrenze `flag_*` nel testo emesso (path B, config del
§55), normalizzando costanti e nomi di variabile:

```
     98  flag_zf = (var_tmp0 == 0)        <-- prima in classifica
     21  flag_sf = ((__int64)var_tmp0 < 0)
     15  flag_of = 0
      6  flag_zf = ((v3 - 0x40) == 0)     <-- fusione RIUSCITA (sottrazione inline)
```

Il contesto reale di una sopravvissuta (`sample1/sub_140001010.hlil.c:116`):

```c
var_tmp0 = ((uint32_t)v8 - 1);
flag_zf  = (var_tmp0 == 0);      // <- nessuno la legge
if (var_tmp0 == 0) { ... }       // <- il ramo usa il TEMPORANEO, non il flag
```

**La fusione dei flag aveva gia' funzionato.** La condizione del salto e' gia'
riscritta sull'espressione; quello che resta e' uno STORE MORTO. La voce «SSA
MLIL per i flag» della lista puntava al rimedio sbagliato — il §56 lo aveva gia'
mostrato di lato (la SSA non fonde nulla), qui si vede perche': non c'era niente
da fondere.

## 57.2 Perche' nessuna delle DCE esistenti lo prendeva

Due DCE erano gia' cablate, e nessuna delle due poteva vederlo:

| passata | dove | perche' fallisce |
|---|---|---|
| `eliminate_dead_flag_writes_cfg` (`lib.rs:27260`) | sul **MLIL** | gira PRIMA della fusione, quando il salto legge ancora il flag: li' e' genuinamente vivo |
| `eliminate_dead_stores` (`hlil_structuring.rs`) | sull'**HLIL** | decide con `count_reads_stmts(body, n) == 0`, cioe' sul TOTALE delle letture nella funzione |

E' la fusione a CREARE la morte, e dopo di lei non ripassa nessuno. Il secondo
criterio non discrimina sui flag: `flag_zf` viene riscritto decine di volte nello
stesso corpo e **una sola** lettura in fondo tiene in vita TUTTI i suoi store.

⚠ Il mio primo script di misura ha commesso lo stesso errore — contava le
letture per-file e per-nome e rispondeva «0% morti», in contraddizione con il
codice che avevo appena letto. E' l'errore contro cui il commento su `var_tmp0`
in `lib.rs:23153` mette in guardia da mesi. La liveness va fatta sul grafo.

## 57.3 La passata: `eliminate_dead_flag_stores`

`crates/rustre-il-hlil/src/hlil_structuring.rs`, gate **`RUSTRE_HLIL_FLAGDCE`**
(opt-in), innestata subito PRIMA di `eliminate_dead_stores`. Liveness
all'indietro sugli statement, non conteggio di letture:

* `If`/`Switch`: unione dei rami; `While`/`DoWhile`/`For`: si assume vivo tutto
  cio' che il corpo legge (approssimazione dal lato sicuro dell'arco
  all'indietro, senza punto fisso);
* si cancella solo un RHS senza `Call`;
* **punto fisso su `Label -> insieme vivo`**, propagato a ogni `Goto` che la
  punta (`Goto(a)` <-> `Label("loc_{a:x}")`); si parte ottimisti e si cancella
  SOLO nel giro finale. Converge in **3 giri**.

### Due passi falsi, entrambi misurati e non dedotti

1. **Binario stantio.** `cargo build --release -p rustre-decompiler` NON
   ricostruisce gli examples: serve `--examples`. La prima misura girava col
   binario di 20 minuti prima e dava «effetto zero». E' la trappola che
   CLAUDE.md segnala, e l'indizio che l'ha smascherata e' che il lato di
   controllo risultava identico al giro precedente byte per byte.
2. **Veto globale troppo forte.** Con `has_goto_or_label` che sospendeva
   l'intera funzione: **43 funzioni su 43 rinunciavano** (tutti i 143 store),
   perche' a quel punto della pipeline i goto ci sono ancora tutti — li tolgono
   le passate testuali a valle, quando l'AST non esiste piu'. Quel punto e'
   l'unico disponibile, quindi le etichette vanno trattate davvero. Rimosso il
   veto e messo il punto fisso: **rimossi 3 -> 82 su 143**.

## 57.4 Misura (3 bucket, 143 funzioni, stesso binario sui due lati)

| | `flag_` | `var_tmp0` | righe | goto | switch | dati | file |
|---|---|---|---|---|---|---|---|
| estesa (§55) | 386 | 487 | 7875 | 58 | 25 | 125 | 143 |
| **+`FLAGDCE`** | **237** (−38,6%) | **375** (−23,0%) | 7712 (−163) | 58 | 25 | 125 | 143 |

**La cascata prevista si e' verificata**: `var_tmp0` sopravviveva perche' aveva
DUE letture (la riga morta e l'`if`); tolta la riga morta ne resta una, e
`inline_adjacent_hlil_temps` — gia' cablata a valle e in attesa esattamente di
quel caso — lo assorbe da se'. Un solo intervento chiude due voci della lista.

`param` cala 1119 -> 1110: e' un conteggio di OCCORRENZE di `a1..a4`, e togliere
codice morto che le nominava lo riduce senza perdere nulla. Verificato dove
conta: le **140 firme sono identiche byte per byte** fra i due lati.

## 57.5 Verifiche

* **Comportamento** (`behavior.py --path-b`): **10 AGREE, 2 LINK_FAIL** —
  identico al riferimento di path B del §54. Zero regressioni, zero guadagni:
  la passata toglie codice morto, e il codice morto non cambia il comportamento.
  E' l'esito atteso, ed e' il motivo per cui va misurato lo stesso.
* **Test**: 6 unitari nuovi (469 vs 463 nel crate HLIL), fra cui il caso che
  `eliminate_dead_stores` sbaglia (lettura lontana che salverebbe uno store
  sovrascritto prima) e i due sulle etichette.
* `cargo test -p rustre-decompiler --lib`: **1337 passati, 0 falliti**.

## 57.6 Un test committato che contraddiceva il codice committato

`indirect_jumpout_raised_to_tail_call_only_for_plain_identifiers` falliva **gia'
prima** di questa modifica — verificato mettendo da parte le mie modifiche e
rieseguendolo. Contraddizione interna a HEAD: il codice di #6620 solleva anche
la forma di memoria (`plain || mem`), il test asseriva che `JUMPOUT(*rax)`
restasse grezzo, codificando l'intento piu' stretto della prima stesura.

Ha ragione il codice: `jmp [rax]` E' una chiamata di coda indiretta e
`return (*rax)();` ne e' la resa esatta; ed e' quel ramo a portare i `JUMPOUT`
emessi da 18 a 0. Test riallineato e rinominato
`indirect_jumpout_raised_to_tail_call_for_identifiers_and_memory`, con il
perche' scritto dentro. `off_…` resta intatto: la' l'operando e' un simbolo di
DATO e chiamarlo produrrebbe una dichiarazione implicita.

## 57.7 Dove siamo

`RUSTRE_HLIL_FLAGDCE` e' opt-in. Prima di accenderlo per difetto manca la
verifica su tutti e 12 i bucket con `measure.sh --compare`; sui 3 rigenerati e'
neutro sul comportamento e migliora due contatori su due.

Restano: i 237 `flag_` vivi (in buona parte combinazioni vere,
`if ((flag_zf == 1) | (flag_sf != flag_of))`, che `fold_flag_combos` non chiude),
i 375 `var_tmp0` con piu' di una lettura reale, e i 58 `goto`.

---

# Round 58 — 2026-08-18 — Copy propagation dei temporanei, e l'ORDINE che decide tutto

## 58.1 Il fronte, dopo la DCE del §57

Dopo `FLAGDCE` i 237 `flag_*` sopravvissuti sono genuinamente VIVI, e in buona
parte COMBINAZIONI:

```
  6  if ((flag_zf == 1) | (flag_sf != flag_of))       <-- <= con segno
  6  if ((flag_cf == 0) & (flag_zf == 0))             <-- > senza segno
  6  if (((var_tmp0 == 0) == 1) | (flag_sf != flag_of))
```

La terza riga e' la fusione ferma a meta' strada: `zf` e' stato assorbito (dopo
la DCE era a uso singolo), `sf` e `of` no. Il collo di bottiglia non e' piu'
cosmetico — e' il temporaneo.

`propagate_expressions`, gia' cablata, rinuncia per costruzione: propaga solo
assegnazioni a **uso singolo** e solo nello statement **immediatamente
successivo**. L'abbassamento di un `cmp` produce un temporaneo con TRE letture.

## 58.2 `propagate_pure_temps`

`crates/rustre-il-hlil/src/hlil_structuring.rs`, gate **`RUSTRE_HLIL_TEMPPROP`**
(opt-in). Duplica un RHS PURO in tutti gli usi del live range e cancella la
definizione. Duplicare un'espressione senza effetti e' lecito; il solo rischio e'
che gli operandi cambino. Condizioni, tutte verificate prima di toccare qualcosa:

* RHS senza `Call`;
* nella finestra fra definizione e ridefinizione nessuno SCRIVE una variabile
  letta dal RHS (controllo profondo, corpi annidati compresi);
* nessun `Goto`/`Label` nella finestra — il flusso potrebbe entrarci in mezzo;
* nessun CICLO nella finestra legge il temporaneo — la' l'espressione sarebbe
  rivalutata a ogni giro.

## 58.3 ⚠ L'ORDINE era tutto, e la prima collocazione era SBAGLIATA

Messa PRIMA di `fold_flag_combos` — che sembrava ovvio, visto che il folder
"vuole gli operandi veri" — la passata **sabota il folder**. Il folder riconosce
la forma CON il temporaneo, e stava gia' chiudendo quei confronti:

```c
flag_zf = ((v8 - 65535) == 0);
if (v8 > 0xFFFF) {                                   // <- fusione RIUSCITA
```

Propagando prima si distrugge il motivo che cerca:

```c
flag_of = (((__int64)v8 < 0) != (0xFFFF < 0)) & ...;
flag_sf = ((v8 - 65535) < 0);
if (((v8 == 0xFFFF) == 0) & (flag_sf == flag_of)) {  // <- fusione FALLITA
```

Misurato: `flag_` 237 -> **315** (+33%) e la DCE del §57 che scende da 82 a 65
rimozioni. Spostata DOPO le fusioni, raccoglie solo cio' che quelle non hanno
preso, e il danno sparisce.

E' la stessa forma della regola gia' in CLAUDE.md («una passata di riparazione
sintattica deve girare per ULTIMA»): qui il vincolo e' l'opposto — una passata
che NORMALIZZA deve girare DOPO chi riconosce le forme non normalizzate.
Generalizzando: **prima chi fa pattern matching su una forma grezza, poi chi
quella forma la distrugge.**

## 58.4 Misura (3 bucket, 143 funzioni, stesso binario su tutti i lati)

| | `goto` | `var_tmp0` | `flag_` | param | switch | dati | file | righe |
|---|---|---|---|---|---|---|---|---|
| estesa (§55) | 58 | 487 | 386 | 1119 | 25 | 125 | 143 | 7875 |
| +`FLAGDCE` (§57) | 58 | 375 | 237 | 1110 | 25 | 125 | 143 | 7712 |
| +`TEMPPROP` **prima** | 58 | 313 | **315** ✗ | 1115 | 25 | 125 | 143 | 7697 |
| **+`TEMPPROP` dopo** | 58 | **281** | **237** | 1108 | 25 | 125 | 143 | **7653** |

Cumulativo sulle due passate: temporanei **−42,3%**, flag **−38,6%**, **−222
righe**. Nessun contatore peggiorato.

## 58.5 Verifiche

* **140 firme identiche byte per byte** al riferimento.
* **Zero `var_tmp*` usati-e-mai-definiti** — il rischio specifico del cancellare
  una definizione, controllato esplicitamente sull'intero albero emesso.
* **Comportamento**: 10 AGREE / 2 LINK_FAIL, identico al riferimento di path B.
* **Test**: 6 unitari nuovi (475 vs 469 nel crate HLIL), uno per ciascuna delle
  quattro condizioni di sicurezza piu' il caso base e la ridefinizione.
  `cargo test -p rustre-decompiler --lib`: 1337 passati, 0 falliti.

## 58.6 Dove siamo

Due gate opt-in nuovi, `RUSTRE_HLIL_FLAGDCE` e `RUSTRE_HLIL_TEMPPROP`, che vanno
accesi INSIEME e in quest'ordine. Manca la verifica su tutti e 12 i bucket con
`measure.sh --compare` prima di renderli default.

Restano: 237 `flag_` (combinazioni che `fold_flag_combos` non chiude), 281
`var_tmp0` (con piu' di una lettura reale o bloccati da una delle quattro
guardie), e i 58 `goto`.

---

# Round 59 — 2026-08-18 — Path B PERDE 57 CHIAMATE. Il difetto piu' grave trovato finora

## 59.1 Come e' saltato fuori

Cercando i 58 `goto` residui. Il primo esaminato (`_initterm_e`, un solo goto)
non era un problema di leggibilita':

```c
while (1) {
    v3 = *(__int64 *)v2;
    if (!((v3 == 0) == 1)) break;      // se il puntatore NON e' nullo, ESCE
loc_1400027ae:
    v2 = (v2 + 8);
    ...
}
return;
v3 = ((__int64 (*)())v3)();            // <- la chiamata vera, DOPO il return
if (((uint32_t)v3) == 0) goto loc_1400027ae;
```

`_initterm_e` deve invocare i puntatori a funzione dell'array. Nel codice emesso
la chiamata sta **dopo il `return`**, irraggiungibile, e il `goto` che la
ricollegherebbe al ciclo vive anch'esso nel tratto morto. **La funzione emessa
non chiama mai nulla.** Stessa forma esatta in `__dyn_tls_init`, che quindi non
invoca mai i callback TLS.

## 59.2 La misura

`codamorta.py` (nuovo, in scratchpad): dentro un blocco, dopo un terminatore
(`return`/`break`/`continue`/`goto`) allo stesso livello di graffa, tutto cio'
che segue fino alla chiusura e' irraggiungibile — salvo un'ETICHETTA, che
riapre un ingresso.

Sui 3 bucket (143 funzioni di path B):

| | valore |
|---|---|
| file con coda irraggiungibile | **41 su 143 (28,7%)** |
| righe morte | ~1240 |
| **chiamate mai eseguite** | **57** |
| goto in coda morta | 6 su 58 |

I `goto` erano il sintomo minore: **6 su 58**. Il fronte e' la coda morta.

## 59.3 Le quattro verifiche che rendono il dato usabile

1. **Non l'ho causato io.** Identico su `base_min` (solo `RUSTRE_HLIL=1`), su
   `gt4` (config estesa) e su `tp2` (con i due gate nuovi): 41 file, 57 chiamate,
   sempre. Le passate dei §57-58 non c'entrano.
2. **Non e' `CFGLOOP`.** Con `RUSTRE_HLIL_CFGLOOP=0` il conto non si muove.
3. **Path A e' CORRETTO sulla stessa funzione.** Su `__dyn_tls_init` path A
   emette la chiamata DENTRO il ciclo, dov'e' il suo posto:
   ```c
   do {
       result = *iter;
       if (result != 0) { ((__int64 (*)())result)(a1, a2); }
       iter += 8;
   } while (iter != v3);
   ```
   E' quindi un difetto di **path B soltanto** — un divario di parita', il piu'
   grave misurato finora, perche' e' di CORRETTEZZA e non di leggibilita'.
4. **Verificato a mano** su un caso piccolo (`__dyn_tls_init`, 2 righe morte) e
   uno grande, non solo contato dallo script.

## 59.4 La causa, dalla forma del CFG

CFG originale: `A` (carica + testa) -> se zero salta a `L`; altrimenti `B`
(la chiamata) -> cade su `L`; `L` = `C` (incremento, test, arco all'indietro su
`A` oppure uscita su `D`).

Il ciclo naturale dell'arco all'indietro `C->A` contiene **A, B e C**. Path B ne
ha preso solo **A e C**, ed ha esiliato `B` fuori dal ciclo *e* dopo il blocco
di uscita `D`. Da qui tutto: il `break` al posto della chiamata, la coda morta,
il `goto` all'indietro.

## 59.5 ⚠ Il calcolo corretto ESISTE NELLA CATENA ED E' SPENTO

`crates/rustre-il-hlil/src/hlil_control_flow_recovery.rs` — **981 righe, 7
test, `pub mod`** — contiene `natural_loop_body`, e la sua implementazione e'
quella giusta: raggiungibilita' all'indietro dal sorgente dell'arco, fermandosi
all'header. **Includerebbe `B`.**

**Zero chiamanti fuori dal proprio file.** Verificato con grep su tutti i crate:
le sole occorrenze altrove sono un `ControlFlowRecovery` omonimo e scorrelato in
`rustre-arch-wasm`.

Espone anche, tutto inutilizzato:
* `cfg_from_hlil` / `cfg_from_hlil_level` — costruisce un CFG DAGLI statement HLIL;
* `recover_loops`, `innermost_loops`, `nesting_depth_of`;
* **`reachable_blocks_petgraph`** — cioe' esattamente lo strumento che direbbe
  quali statement sono irraggiungibili, che e' il difetto di questo round.

E' il caso da manuale della diagnosi generale di questa sessione: la capacita'
non manca, e' **spenta**. Vedi il §12 e
`project_decompiler_catena_2026-08-18` in memoria.

Nota metodologica: `find_loop_exit`, nello stesso file, itera un `HashSet` e
ritorna la PRIMA uscita trovata — con piu' uscite l'esito dipende dall'ordine di
hash, quindi non e' deterministico. Da sistemare quando lo si cabla, non dopo.

## 59.6 Perche' nessuna metrica lo aveva visto

* `check.sh` no: il codice morto **compila** perfettamente.
* `behavior.py` no: nessuna delle 41 funzioni colpite e' nel campione delle 12
  comuni, e sulle campionate path B resta 10 AGREE contro 5 di path A.
* Il punteggio di confidenza no.

E' esattamente la classe «sicuro di se' e sbagliato» contro cui CLAUDE.md mette
in guardia, e la stessa forma del difetto di `count_set_flags`. **Una metrica
nuova l'ha trovata al primo colpo**, come da nota in memoria: ogni misura nuova
rivela prima un difetto che le misure esistenti erano strutturalmente cieche a
vedere.

## 59.7 Conseguenza sull'obiettivo

«Path B unico» **non e' raggiungibile finche' path B perde chiamate**. Questo
difetto viene prima dei goto, dei flag e dei temporanei: quelli sono
leggibilita', questo e' correttezza. E' il prossimo lavoro.

---

# Round 60 — 2026-08-18 — Chiamate perse: causa TROVATA e in parte chiusa

## 60.0 ⚠ CORREZIONE al §59.5

Il §59.5 attribuiva il difetto al fatto che il `natural_loop_body` corretto vive
solo nel modulo inutilizzato `hlil_control_flow_recovery`. **E' sbagliato, e
l'errore e' stato mio: avevo letto la riga 8678 del `lib.rs` di
`rustre-decompiler` invece che di `rustre-il-hlil`** — stesso numero, file
diverso, e li' c'e' `retype_scalar_only_xmm`.

Il modulo `structuring` che path B USA DAVVERO ha il suo `natural_loop_body`
(`rustre-il-hlil/src/lib.rs:8678`) ed e' **corretto** anch'esso: raggiungibilita'
all'indietro dal latch fermandosi all'header. Il corpo del ciclo NON e' il
difetto.

Resta vero, e verificato, che `hlil_control_flow_recovery` (981 righe, 7 test,
`pub mod`) non ha alcun chiamante: e' capacita' spenta, ma non e' questa la
causa. Il §59 va letto con questa correzione.

## 60.1 La causa vera

In `emit_loop`, forma «header con statement E test in testa»
(`rustre-il-hlil/src/lib.rs:10216`), si emette:

```rust
body.push(If { cond: !guard, then_body: [Break] });   // il break deve cadere su `outside`
out.push(While { cond: 1, body });
self.queue_break_exit(break_exit, Some(outside));
self.emit_pending_exits(mark, out);                   // <- inserisce un blocco QUI
return Some(outside);                                 // <- e `outside` arriva DOPO
```

Un `break` atterra su cio' che SEGUE il costrutto. Due valori diversi si
contendono quel posto:

* `outside` = il ramo del test in testa che lascia il ciclo — **dimostrabilmente**
  dove va il controllo quando la guardia fallisce;
* `break_exit` = `ipdom(header)` quando le uscite sono piu' d'una.

Su `__dyn_tls_init` le uscite sono DUE, quindi `break_exit` = il blocco di
`return` e `outside` = il blocco della CHIAMATA. `emit_pending_exits` infila il
primo fra il `while` e il secondo: il `break` atterra sul `return` (la funzione
esce senza chiamare) e il blocco della chiamata finisce dopo un `return`,
irraggiungibile.

## 60.2 Un commento nel sorgente che dice il falso

Sopra `queue_break_exit` c'e' scritto che la correzione «e' RITIRATA dietro
l'opt-in `RUSTRE_HLIL_BREAKFIX=1`» e che «il gate resta spento». Il codice dice
il contrario:

```rust
let break_ok = env("RUSTRE_HLIL_BREAKFIX") == "0" || "false"
            || self.loop_ctx.last().is_some_and(|&(_, e)| e == Some(c));
```

Con la variabile NON impostata `is_ok_and` e' falso, quindi la correzione e'
**attiva per difetto** e la si spegne mettendo il gate a `0`. Misurato su
sample6_c:

| | goto | file con coda morta | chiamate perse |
|---|---|---|---|
| `BREAKFIX=0` | 22 | 7 | **15** |
| `BREAKFIX=1` | 25 | 14 | 19 |
| **non impostato** | 25 | 14 | **19** |

Cioe': non solo il gate e' acceso quando il commento lo dice spento, ma nella
configurazione attiva perde PIU' chiamate. E' il terzo commento falso trovato in
questa sessione (cfr. [[feedback_difetto_nella_frase]] in memoria).

## 60.3 #6760 — il bersaglio del `break` e' `outside`

Gate **`RUSTRE_HLIL_TOPTEST_BREAK`** (opt-in). In questa forma si registra
`outside` come bersaglio del `break` e non si emette NULLA fra il `while` e lui:
e' l'invariante da cui dipende la correttezza del `break`.

Prima stesura, misurata: chiamate perse 57 -> 45, file con coda morta 41 -> 20,
goto in coda morta 6 -> **0** — ma **JUMPOUT 0 -> 15**, perche' le uscite
secondarie restavano in `pending_exits` senza che nessuno le emettesse, e un
`goto` senza etichetta degrada a `JUMPOUT`. Scambiare 12 chiamate perse per 15
`JUMPOUT` non e' un affare.

## 60.4 #6760b — svuotamento finale delle uscite pendenti

Le uscite secondarie si emettono in coda alla FUNZIONE
(`structure_function`, dopo `emit_sequence(entry)`), dove un'etichetta e' sempre
valida e nessun `break` dipende dall'adiacenza.

| config minima | goto | JUMPOUT | file coda morta | chiamate perse | righe morte |
|---|---|---|---|---|---|
| prima | 76 | 0 | 41 | 57 | 1234 |
| #6760 | 88 | **15** ✗ | 20 | 45 | 1129 |
| **#6760 + b** | 109 | **0** | **20** | **45** | **1129** |

`__dyn_tls_init` verificato a mano: la chiamata al puntatore a funzione e' ora
RAGGIUNGIBILE, il `break` ci atterra e il `goto loc_X` richiude il ciclo.

## 60.5 Con la configurazione completa il costo quasi sparisce

Gli altri gate riassorbono i salti:

| | goto | JUMPOUT | chiamate perse | file coda morta | `tmp0` | flag | dati | file |
|---|---|---|---|---|---|---|---|---|
| §58 (`tp2`) | 58 | 0 | 57 | 41 | 281 | 237 | 125 | 143 |
| **+#6760/b** | 61 (+3) | **0** | **48** (−9) | **35** | 290 (+9) | 237 | 125 | 143 |

* **140 firme identiche byte per byte**;
* **comportamento invariato**: 10 AGREE / 2 LINK_FAIL;
* test: 475 nel crate HLIL, 1337 nel decompilatore, 0 falliti.

Nota onesta: il guadagno e' PIU' PICCOLO nella configurazione completa (48
chiamate perse contro le 45 della minima, 35 file contro 20). I gate
interagiscono, e non ho ancora isolato quale riduca l'efficacia della correzione.
Non e' una regressione — e' un guadagno minore di quanto la misura isolata
prometteva, e va detto.

## 60.6 Dove siamo

Chiamate perse **57 -> 48**. La classe non e' chiusa: restano 48 chiamate in 35
file, che sono altre forme di loop (non quella a test in testa). Il metodo per
trovarle ora c'e' (`codamorta.py`) e la causa di questa e' capita fino in fondo.

Tre gate opt-in nuovi in due round, da accendere INSIEME:
`RUSTRE_HLIL_FLAGDCE`, `RUSTRE_HLIL_TEMPPROP`, `RUSTRE_HLIL_TOPTEST_BREAK`.

---

# Round 61 — 2026-08-18 — ⚠ CORREZIONE ai §59-60: i numeri erano gonfiati 5x, e la correzione e' COMPLETA

## 61.1 Il difetto nella misura

`codamorta.py` riconosceva come punto d'ingresso solo `etichetta:`
(`^\s*\w+:\s*$`). **`case 52:` e `default:` non passano quel filtro** — sono due
token. Quindi dopo il primo `break;` dichiarava morto tutto il resto di ogni
`switch`, e la macchina a stati del relooper e' fatta esattamente cosi'.

Falso positivo isolato leggendo il file peggiore (`sub_140001a00`, 190 righe
«morte»): erano i `case` di un dispatch loop, tutti raggiungibili.

E' la terza volta in questa sessione che una misura nuova rivela per prima un
difetto in se stessa — vedi `feedback_misurare_non_dedurre` in memoria. La
lezione qui e' specifica: **un riconoscitore di punti d'ingresso deve conoscere
TUTTE le forme di etichetta del linguaggio**, e in C sono tre.

## 61.2 I numeri corretti

| snapshot | file con coda morta | **chiamate perse** | righe morte |
|---|---|---|---|
| minima, prima (`tt0`) | 28 | **12** | 124 |
| minima, #6760 (`tt1`) | 1 | **0** | 19 |
| minima, #6760+b (`tt2`) | 1 | **0** | 19 |
| completa, prima (`tp2`) | 25 | **9** | 103 |
| **completa, dopo (`full`)** | 13 | **0** | 43 |

### Cosa cambia rispetto a quanto scritto nei §59-60

* **Il difetto era 5 volte piu' piccolo**: 12 chiamate perse, non 57. Il §59
  titolava «path B PERDE 57 CHIAMATE»: la cifra e' sbagliata, la classe no.
* **La correzione e' COMPLETA, non parziale**: 12 -> **0** (minima) e 9 -> **0**
  (completa). Il §60 riportava «57 -> 48», cioe' sottostimava il rimedio mentre
  sovrastimava il problema. Entrambi gli errori vengono dallo stesso bug di
  misura.
* **Sparisce l'anomalia del §60.5**, dove il guadagno sembrava minore nella
  configurazione completa che nella minima: era un artefatto: 9->0 e 12->0 sono
  entrambe chiusure totali. Non c'e' nessuna interazione fra gate da isolare.
* **Restano VERI**: i due casi letti a mano (`_initterm_e`, `__dyn_tls_init` non
  chiamavano nulla), la causa (`break_exit` != `outside`), il fatto che path A
  fosse corretto sulle stesse funzioni, e che il commento su
  `RUSTRE_HLIL_BREAKFIX` dica il falso.

## 61.3 Verifica finale sulle due funzioni d'origine

`_initterm_e`, config completa:

```c
while (1) {
    v3 = *(__int64 *)v2;
    if (!((v3 == 0) == 1)) { break; }     // puntatore non nullo -> esce
loc_X:
    v2 = (v2 + 8);
    if (v2 < v1) { continue; } else { v3 = 0; }
    sp = (sp + 40); return;
}
v3 = ((__int64 (*)())v3)();               // LO CHIAMA
if (((uint32_t)v3) == 0) { goto loc_X; }  // se ok, riprende il ciclo
```

E' la semantica vera della funzione. Idem `__dyn_tls_init`.

## 61.4 Le 13 code residue non sono un difetto di correttezza

Ispezionate: sono epiloghi DUPLICATI dopo un `return`
(`sp = (sp + 40); return v3;` ripetuto), 43 righe in tutto, **zero chiamate**.
Codice morto innocuo, non codice sbagliato. Vale la pena toglierlo per pulizia,
non per fedelta'.

## 61.5 Stato consolidato dei tre gate nuovi

Da accendere INSIEME, nell'ordine in cui la pipeline li applica:
`RUSTRE_HLIL_FLAGDCE`, `RUSTRE_HLIL_TEMPPROP`, `RUSTRE_HLIL_TOPTEST_BREAK`.

| | goto | JUMPOUT | `tmp0` | `flag_` | chiamate perse | dati | file | firme |
|---|---|---|---|---|---|---|---|---|
| §55 estesa | 58 | 0 | 487 | 386 | 12 | 125 | 143 | 140 |
| **tutti e tre** | 61 | **0** | **290** | **237** | **0** | 125 | 143 | 140 identiche |

Temporanei **−40,5%**, flag **−38,6%**, chiamate perse **azzerate**, JUMPOUT a
zero, comportamento invariato (10 AGREE / 2 LINK_FAIL), 475 + 1337 test verdi.
Costo: **+3 goto**.

---

# Round 62 — 2026-08-18 — Verifica su TUTTI E 12 i bucket: 11342 file per lato

## 62.1 Perche' i 3 bucket non bastavano

I §57-61 misuravano su 3 bucket (143 funzioni di path B). Sono i programmi C
piccoli del corpus: NON rappresentativi. Sull'intero corpus la stessa classe di
difetto e' venti volte piu' grande, e un gate che li' sembrava neutro non lo e'.

Rigenerati **11342 file per lato** con la stessa build, `all_before` (config
estesa del §55) contro `all_after` (+ i tre gate nuovi).

## 62.2 Contatori, corpus intero

| | goto | JUMPOUT | `var_tmp*` | `flag_` | switch | dati | righe |
|---|---|---|---|---|---|---|---|
| prima | 8913 | 7 | 59619 | 51397 | 725 | 7937 | 946284 |
| **dopo** | 9468 (+555) | **2** | **37022** (−37,9%) | **36352** (−29,3%) | 726 | 7935 (−2) | 921593 (−2,6%) |

## 62.3 Code irraggiungibili, corpus intero

| | file con coda morta | **chiamate perse** | righe morte |
|---|---|---|---|
| prima | 1780 | **2556** | 19644 |
| **dopo** | 984 (−44,7%) | **1862** (−694, −27%) | 10611 (−46,0%) |

Sui 3 bucket la classe valeva 12 chiamate; sui 12 ne vale **2556**. La misura
ristretta non sbagliava di segno, sbagliava di due ordini di grandezza.

## 62.4 ⚠ Il `-2` sui dati era il sintomo di una regressione VERA

Due file su 11342 perdevano un `static uint8_t`. Inseguito invece di
archiviarlo, perche' e' la classe che ha gia' ingannato due volte questa
sessione (§51.1, §53.2):

`sample4_go/sub_14001fa32`: 530 righe -> 394, e **3 chiamate DISTINTE sparite**
(`runtime_scanConservative`, `runtime_putempty`,
`runtime___stackScanState__getPtr`).

**Bisezione**: `FLAGDCE` e `TEMPPROP` lasciano il file identico
(530 righe, 11 dati, 84 chiamate). Il colpevole e' **`TOPTEST_BREAK`**.

**Prima ipotesi, falsificata**: avevo saltato anche `queue_break_exit`, quindi
l'uscita secondaria non veniva REGISTRATA. Rimessa (#6760c): **nessun cambio**.
Non era quello.

**Dove sta davvero**: la sonda gia' esistente `RUSTRE_HLIL_DEBUG` riporta
**936 blocchi mai emessi in ENTRAMBE le configurazioni, zero raggiungibili** —
quindi l'emettitore produce lo stesso insieme di blocchi. Le chiamate spariscono
DOPO: emesse in coda alla funzione (#6760b) finiscono dietro un `return`, e una
passata a valle le rimuove come irraggiungibili. Lo svuotamento finale mette i
blocchi in un posto valido per l'ETICHETTA ma non per la RAGGIUNGIBILITA'.

**Costo misurato**: **2 file su 11342**, 6 chiamate distinte, zero guadagnate.

## 62.5 Il bilancio

| | |
|---|---|
| chiamate recuperate | **+694** |
| chiamate perse | **−6** (2 file) |
| rapporto | **116:1** |
| costo in `goto` | +555 (+6,2%) |
| `JUMPOUT` | 7 -> **2** (migliora) |

Il rapporto e' schiacciante, ma le 6 perse sono una regressione vera e va
scritto: non e' un guadagno netto puro, e' un guadagno con un costo noto,
localizzato e riproducibile. Il difetto residuo ha una causa capita — un blocco
emesso in coda non e' raggiungibile — e la riparazione giusta e' emetterlo
DOVE un `goto` lo raggiunge, non dove l'etichetta e' comoda.

## 62.6 Metodo

Tre cose che questo round conferma:
1. **misurare sul corpus intero prima di dichiarare chiuso qualcosa**: 12 contro
   2556 sulla stessa classe;
2. **inseguire anche un delta di 2**: quel `-2` nascondeva la sola regressione
   dei tre gate;
3. **la sonda giusta esisteva gia'** (`RUSTRE_HLIL_DEBUG`) e ha falsificato in
   un colpo l'ipotesi «blocchi persi», che avrei altrimenti inseguito a lungo.

---

# Round 63 — 2026-08-18 — Separare l'OVER-SCAN dal difetto: il numero onesto e' 1041 -> 381

## 63.1 Il residuo Go/C# non era tutto un difetto

Il §62 lasciava 1862 «chiamate perse» concentrate in Go (1220) e C# (416).
Aperta una: `sample9_go/sub_140001fea`, coda morta con la forma classica
dell'epilogo di crescita dello stack di Go:

```c
sp = (sp + 32);
return;
*(__int64 *)(sp + 8) = v2;                       // salva gli argomenti
v2 = runtime_morestack_noctxt_abi0();            // chiama morestack
v2 = *(__int64 *)(sp + 8);                       // li ripristina
return type_descriptor_for__eq__7_internal_cpu_option();   // rientra
```

**Disassemblata la funzione** (`disasm_dump`, intervallo
`0x140001fea..=0x140002258`): contiene **due sole `call`, entrambe a
`0x1400026A0`** (`runtime_memequal`). **Nessuna chiamata a `morestack`.** Quelle
istruzioni vengono da OLTRE l'estensione della funzione.

E' l'over-scan di `.pdata` che CLAUDE.md documenta come deliberato («senza, le
funzioni vengono troncate») e il cui costo dichiarato e' esattamente questo: «le
analisi senza filtro di raggiungibilita' vedono istruzioni estranee». La mia
misura era una di quelle analisi.

## 63.2 Il criterio che separa le due cose

Una regione morta che arriva alla FINE del corpo puo' essere over-scan. Una
regione morta **seguita da altro codice VIVO** non puo' esserlo: e' codice della
funzione che l'emettitore ha messo dove non ci si arriva.

`codamorta2.py` classifica su questo criterio.

| | regioni | righe | **chiamate** |
|---|---|---|---|
| **IN MEZZO (difetto)** prima | 2991 | 13025 | **1041** |
| **IN MEZZO (difetto)** dopo | 572 (−80,9%) | 4120 (−68,4%) | **381 (−63,4%)** |
| in coda (over-scan) prima | 922 | 6619 | 1515 |
| in coda (over-scan) dopo | 882 | 6491 | 1481 |

L'over-scan resta **praticamente invariato** (−4%), come dev'essere: non e' il
bersaglio di questa correzione. Che i due gruppi si muovano in modo cosi' diverso
e' la prova che il criterio separa davvero due popolazioni, e non taglia a caso.

## 63.3 Il numero da citare

**Chiamate perse per difetto dell'emettitore: 1041 -> 381, −63,4%.**

Non «2556 -> 1862» del §62, che sommava l'over-scan e sottostimava quindi
l'effetto (−27% invece di −63%). E non «12 -> 0» dei §57-61, che misurava tre
bucket C non rappresentativi.

E' la terza revisione dello stesso numero in questa sessione. Tutte e tre sono
andate nella stessa direzione: **la misura grezza sbagliava, e ogni raffinamento
ha reso il difetto piu' piccolo e la correzione piu' efficace**.

## 63.4 Distribuzione per bucket (chiamate perse totali, §62)

| bucket | prima | dopo |
|---|---|---|
| i cinque bucket C | 3 ciascuno | **0 ciascuno** |
| sample9_go / sample4_go | 816 / 806 | 613 / 607 |
| sample10_cs / sample5_cs | 345 / 325 | 216 / 200 |
| sample7_cpp | 135 | 126 |
| sample3_rust / sample8_rust | 57 / 57 | 50 / 50 |

I bucket C vanno a ZERO. Il residuo e' Go (65%) e C#, dove l'over-scan e' piu'
pesante — coerente con il §63.1.

## 63.5 Dove va a finire il costo in `goto`

I +555 netti non sono distribuiti: **515 su C# (sample10 258, sample5 257)** e
111 su Go. I cinque bucket C ne prendono **uno a testa**. E 87 file ne PERDONO
136.

Cioe': il costo cade dove il flusso e' gia' irriducibile (macchine a stati C#,
Go), e il guadagno cade dove il codice e' leggibile. E' un compromesso
accettabile ma va detto per intero.

---

# Round 64 — 2026-08-18 — Comportamento verificato sul corpus intero; DUE GATE DIVENTANO PREDEFINITI

## 64.1 Comportamento: identico, funzione per funzione

`behavior.py --path-b` su ENTRAMBI i lati del corpus intero:

| | funzioni | AGREE | LINK_FAIL | NOT_EMITTED |
|---|---|---|---|---|
| prima | 63 | **15** (23,8%) | 4 | 44 |
| dopo | 63 | **15** (23,8%) | 4 | 44 |

`cmp_paths.py`: 19 funzioni confrontabili, **19 identiche, 0 migliorate, 0
peggiorate**. Non solo i totali coincidono — coincide ogni singolo verdetto.
E' l'esito atteso (togliere codice morto e propagare espressioni pure non cambia
la semantica) ed e' il motivo per cui va misurato lo stesso.

## 64.2 Isolato il costo: e' TUTTO di `TOPTEST_BREAK`

Rigenerato un terzo lato con i soli `FLAGDCE` + `TEMPPROP`:

| | goto | JUMPOUT | `var_tmp*` | `flag_` | dati | righe |
|---|---|---|---|---|---|---|
| prima | 8913 | 7 | 59619 | 51397 | 7937 | 946284 |
| **FLAGDCE+TEMPPROP** | **8912** (−1) | 7 | **36943** (−38,0%) | **36713** (−28,6%) | **7937** | 924787 |
| + `TOPTEST_BREAK` | 9468 | 2 | 37022 | 36352 | 7935 | 921593 |

* i due gate «dei nomi» portano **tutto il guadagno sui nomi** con **zero costo**:
  −1 goto, JUMPOUT invariato, dati invariati, **0 chiamate distinte perse in 0
  file**;
* `TOPTEST_BREAK` porta **tutto il guadagno sulle chiamate** (1041 -> 381,
  −63,4%) e **tutto il costo**: +556 goto, −2 dati, 6 chiamate distinte perse in
  2 file, JUMPOUT 7 -> 2 (questo in meglio).

Le due correzioni sono ortogonali, e la misura lo dimostra invece di assumerlo:
`FLAGDCE`+`TEMPPROP` lasciano il difetto delle chiamate a 1039 su 1041, cioe' non
lo toccano affatto.

## 64.3 Decisione

* **`RUSTRE_HLIL_FLAGDCE` e `RUSTRE_HLIL_TEMPPROP` -> DEFAULT-ON.** Si spengono
  con `=0`. Nessun contatore peggiorato su 11342 file, comportamento identico.
* **`RUSTRE_HLIL_TOPTEST_BREAK` resta OPT-IN.** Il bilancio e' fortemente
  positivo (116:1 sulle chiamate) ma include una regressione VERA di 6 chiamate,
  con causa nota: un blocco emesso in coda alla funzione ha un'etichetta valida
  ma non e' RAGGIUNGIBILE. Si accende per difetto quando quella e' riparata.

Non accendere un gate con un guadagno 116:1 puo' sembrare eccessivo. La ragione
e' la lezione di CLAUDE.md sui 2233 parametri fantasma: una regressione di
correttezza che compila e non muove il comportamento e' esattamente quella che
resta dentro per mesi. Sei chiamate perse sono poche, ma sono perse in silenzio.

## 64.4 Le due prove, fatte per DIFFERENZA e non per argomento

Rigenerati tutti e 12 i bucket col binario nuovo e NESSUN gate impostato:

1. **`diff -rq` path B (predefiniti) contro path B (gate espliciti):
   0 differenze su 11342 file.** Il passaggio a default-ON e' esattamente
   equivalente, non «dovrebbe esserlo».
2. **`diff -rq` path A prima/dopo: 0 differenze sui `.c` di produzione.** Le
   modifiche sono davvero solo path B.

E' l'argomento che CLAUDE.md indica come l'unico che sopravvive alle modifiche
concorrenti di altri agenti: un confronto fra due miei snapshot, non una cifra
assoluta.

Test: 475 (HLIL) + 1337 (decompiler), 0 falliti.

## 64.5 Stato di path B

| metrica | §55 (config estesa) | oggi (predefiniti) | con `TOPTEST_BREAK` |
|---|---|---|---|
| `var_tmp*` | 59619 | **36943** | 37022 |
| `flag_` | 51397 | **36713** | 36352 |
| chiamate perse (difetto) | 1041 | 1039 | **381** |
| `goto` | 8913 | **8912** | 9468 |
| `JUMPOUT` | 7 | 7 | **2** |
| dati | 7937 | **7937** | 7935 |
| comportamento | 15/63 | **15/63** | **15/63** |

Due voci della lista utente sono chiuse e attive per difetto: «il-passes
CopyPropagation per i `var_tmp0`» e «SSA MLIL per i flag» (quest'ultima con la
diagnosi corretta: non serviva la SSA, servivano DCE e propagazione).

---

# Round 65 — 2026-08-18 — La regressione di `TOPTEST_BREAK`: quattro ipotesi, tre falsificate

Obiettivo del giro: chiudere le 6 chiamate perse da `RUSTRE_HLIL_TOPTEST_BREAK`,
che e' l'unica cosa che gli impedisce di diventare predefinito — e vale
**1041 -> 381** sulle chiamate perse per difetto (§63).

Non e' chiusa. Ma il campo si e' ristretto molto, e ogni esclusione e' misurata.

## 65.1 Ipotesi 1 — «l'uscita secondaria non viene REGISTRATA». FALSA

Nella prima stesura avevo tolto anche `queue_break_exit`, non solo lo
svuotamento. Rimessa (#6760c): **output identico**, nessuna chiamata recuperata.

## 65.2 Ipotesi 2 — «i blocchi non vengono EMESSI». FALSA

Sonda gia' esistente `RUSTRE_HLIL_DEBUG`: **936 blocchi mai emessi in ENTRAMBE
le configurazioni, ZERO raggiungibili**. L'emettitore produce lo stesso insieme
di blocchi con e senza il gate.

## 65.3 Ipotesi 3 — «un `goto` resta orfano e degrada a JUMPOUT». FALSA

Su `sample4_go/sub_14001fa32`:
* prima: 9 goto, 9 etichette, **0 orfani**;
* dopo: 8 goto, 8 etichette, **0 orfani**.

Nessun salto senza destinazione. (Il singolo `JUMPOUT` del bucket e' altrove.)

## 65.4 Ipotesi 4 — «il relooper ripiega e scarta il suo lavoro». FALSA

`structure_improper_scc` costruisce statement, marca i blocchi come emessi e —
se torna `None` — il chiamante ripiega sui `goto`: un percorso di SCARTO
plausibile. Misurato invece sui due file:

| | `state_` | `switch` | `while` | `if` | righe |
|---|---|---|---|---|---|
| prima | 8 | 1 | **7** | **39** | 530 |
| dopo | 8 | 1 | **2** | **24** | 394 |

Il dispatch del relooper e' **identico** (8 e 1). Spariscono **cinque cicli
annidati e quindici `if`**, col loro contenuto. La perdita e' dentro `emit_loop`,
non nel relooper.

## 65.5 Cosa resta

Sappiamo che: i blocchi sono emessi (65.2), i salti hanno destinazione (65.3),
il relooper non c'entra (65.4), e la registrazione non c'entra (65.1). Eppure
cinque cicli annidati scompaiono.

L'unico meccanismo compatibile con tutte e quattro le misure e' un blocco
**marcato `emitted` il cui vettore di statement viene poi scartato**: cosi'
nessuno lo emette piu' (`emit_pending_exits` lo salta con
`if self.emitted.contains(&t) { continue; }`) e la sonda LOST non lo vede,
perche' guarda `emitted`, non l'output.

Sonda `RUSTRE_DBG_PENDING` aggiunta (effetto ZERO, verificato: `diff -rq` su
sample4_go dà differenze solo in `summary.json`). Su sample4_go: **281 uscite
pendenti, 191 gia' marcate emesse e quindi SALTATE, 90 emesse davvero**.
Quel `191` e' il numero da guardare al prossimo giro: se anche solo una di
quelle e' stata marcata dentro un vettore scartato, il suo codice e' perso.

⚠ La sonda stampa `cfg.entry`, che e' un ID DI BLOCCO e non l'indirizzo della
funzione: non permette di isolare la funzione incriminata. Da correggere prima
di riusarla.

## 65.6 Stato invariato e sicuro

`TOPTEST_BREAK` resta OPT-IN, quindi la regressione **non e' in nessun output
predefinito**. I due gate resi predefiniti nel §64 non sono toccati: 475 test
HLIL verdi, emissione identica.

---

# Round 66 — 2026-08-18 — #6770: una passata cancellava CODICE VIVO. JUMPOUT a ZERO

## 66.1 Le ultime due ipotesi, e la sesta che ha retto

Il §65 ne aveva falsificate quattro. Questo giro ne ha aggiunta una quinta e
trovata la vera.

**Ipotesi 5 — «i blocchi sono marcati emessi ma il loro vettore viene
SCARTATO».** Sonda nuova `RUSTRE_DBG_DISCARD` (effetto ZERO, verificato con
`diff -rq`): `emit_block` emette SEMPRE un'etichetta `loc_<addr>`, quindi un id
in `emitted` la cui etichetta manca dal corpo finale e' un vettore scartato.
Misurato: **0 scartati in ENTRAMBE le configurazioni**, `emessi=121` identico.
**FALSA.** L'emettitore e' innocente: la perdita e' a VALLE.

**Ipotesi 6 — una passata a valle cancella.** Aggiunto l'interruttore
diagnostico `RUSTRE_HLIL_NOUNREACH=1` che spegne
`remove_unreachable_after_terminator`, e chiesto per ESPERIMENTO:

| `sample4_go/sub_14001fa32` | righe | `runtime_scanConservative` |
|---|---|---|
| senza `TOPTEST_BREAK` | 530 | 3 |
| con `TOPTEST_BREAK` | 394 | **0** |
| con `TOPTEST_BREAK` + `NOUNREACH` | **513** | **2** |

Spegnendo la passata il codice torna. Confermata.

## 66.2 Il difetto, e non e' di `TOPTEST_BREAK`

Il codice cancellato:

```c
    goto loc_14001fce9;
}
while (1) {                 // <- cancellato: segue un terminatore...
    var_tmp0 = ...;
    if (var_tmp0 != 0) {
loc_14001fede:              // <- ...ma contiene un'ETICHETTA, annidata
```

`remove_unreachable_after_terminator` azzerava lo stato «morto» solo su un
`HlilStatement::Label` **allo stesso livello**. Un `goto` pero' puo' saltare
DENTRO un costrutto: se un `while`/`if` ha un'etichetta nel corpo, quel
costrutto e' raggiungibile anche quando lo precede un terminatore.

**Il difetto e' GENERALE e preesistente.** `RUSTRE_HLIL_TOPTEST_BREAK` non lo
causa: produce solo la disposizione che lo espone. E' il motivo per cui tutte e
cinque le ipotesi a monte erano false.

Riparazione (#6770): non cancellare uno statement che contenga un'etichetta a
QUALUNQUE profondita'.

## 66.3 Misura, corpus intero (11342 file per lato)

| | goto | **JUMPOUT** | `var_tmp*` | `flag_` | **dati** | righe |
|---|---|---|---|---|---|---|
| predefinito (§64) | 8912 | 7 | 36943 | 36713 | 7937 | 924787 |
| **+#6770** | 8978 (+66) | **0** | 37112 | 36782 | **7943** (+6) | 925929 |
| +`TOPTEST` (§62) | 9468 | 2 | 37022 | 36352 | 7935 | 921593 |
| **+#6770+`TOPTEST`** | 9541 | **0** | 37203 | 36428 | **7943** (+8) | 922900 |

* **`JUMPOUT` va a ZERO** in entrambe le configurazioni. E' la richiesta esplicita
  dell'utente, e arriva da una riparazione di correttezza, non da una
  soppressione cosmetica.
* **+6 simboli di dato materializzati** ricompaiono.
* **+18 chiamate DISTINTE recuperate**, 0 perse (confronto insiemistico per file).

## 66.4 La regressione del §64 e' CHIUSA

`TOPTEST_BREAK` dopo #6770: **0 chiamate distinte perse in 0 file** (erano 6 in
2 file). Era l'unica cosa che ne impediva l'accensione per difetto.

Difetto «code irraggiungibili in mezzo»: **1066 -> 423 chiamate (−60%)**.

## 66.5 ⚠ La stessa svista era anche nella MISURA

`codamorta2.py` azzerava lo stato morto solo al livello corrente: contava come
morta esattamente la classe che #6770 salva. Corretto (un'etichetta a qualunque
profondita' azzera tutto). Prima della correzione i numeri erano 1039/1088;
dopo, 1017/1066.

Terza volta in questa sessione che lo stesso difetto concettuale sta sia nel
codice sia nello strumento che lo misura. Vale la pena dirlo come regola: **dopo
aver corretto un difetto di ragionamento nel codice, controllare se la misura lo
condivide.**

## 66.6 Test

Due unitari nuovi (477 vs 475): il caso che deve sopravvivere (etichetta
annidata) e il suo controaltare (nessuna etichetta ⇒ si cancella ancora), perche'
senza il secondo la correzione potrebbe aver disattivato la passata senza che
nulla protesti. `cargo test -p rustre-decompiler --lib`: 1337, 0 falliti.

---

# Round 67 — 2026-08-18 — `TOPTEST_BREAK` diventa predefinito. Bilancio della serie 57-67

## 67.1 Comportamento, entrambe le configurazioni

| | funzioni | AGREE | LINK_FAIL |
|---|---|---|---|
| #6770 solo | 63 | 15 (23,8%) | 4 |
| #6770 + `TOPTEST_BREAK` | 63 | 15 (23,8%) | 4 |

`cmp_paths.py`: **19 su 19 identiche**, 0 migliorate, 0 peggiorate, in entrambe.

## 67.2 `RUSTRE_HLIL_TOPTEST_BREAK` -> DEFAULT-ON

E' rimasto opt-in un giro intero per 6 chiamate perse in 2 file su 11342. La
causa non era in quel codice ma in `remove_unreachable_after_terminator`
(#6770); chiusa quella, restano solo guadagni:

* chiamate perse per difetto **1066 -> 423** (−60%);
* chiamate distinte perse **0** in **0** file (erano 6 in 2);
* `JUMPOUT` 0 -> 0, dati 7943 -> 7943, comportamento identico;
* costo: `goto` 8978 -> 9541 (+563), concentrati su C# e Go — i cinque bucket C
  ne prendono uno a testa.

Il compromesso e' esplicito: un `goto` e' onesto e verificabile, del codice
irraggiungibile e' silenziosamente sbagliato.

## 67.3 Le due prove finali, per differenza

* `diff -rq` predefiniti contro gate espliciti: **0 differenze** su 11342 file;
* `diff -rq` path A dall'INIZIO della serie (`all_before`) a oggi: **0
  differenze** sui `.c` di produzione.

Tutto il lavoro dei round 57-67 e' path B, dimostrato e non argomentato.
Test: 477 (HLIL) + 1337 (decompiler), 0 falliti.

## 67.4 Bilancio della serie 57-67, corpus intero

| metrica | inizio (§55) | fine (§67) | |
|---|---|---|---|
| `var_tmp*` | 59619 | **37203** | **−37,6%** |
| `flag_` | 51397 | **36428** | **−29,1%** |
| `JUMPOUT` | 7 | **0** | **azzerati** |
| chiamate perse per difetto | ~1017 | **423** | **−58%** |
| dati materializzati | 7937 | **7943** | +6 |
| `goto` | 8913 | 9541 | +628 (C#/Go) |
| righe | 946284 | 922900 | −2,5% |
| comportamento | 15/63 | **15/63** | identico 19/19 |
| firme | — | — | identiche |
| path A | — | — | **invariato** |

### Le quattro passate, tutte attive per difetto

1. **`eliminate_dead_flag_stores`** (§57) — liveness all'indietro con punto fisso
   sulle etichette. I flag non erano da fondere: erano store morti.
2. **`propagate_pure_temps`** (§58) — copy propagation a piu' usi di RHS puri.
   ⚠ va DOPO `fold_flag_combos`, non prima: prima la sabota (+33% flag).
3. **#6760 `top_test_break`** (§60) — il bersaglio del `break` in un loop a test
   in testa e' `outside`, non `ipdom(header)`.
4. **#6770** (§66) — non cancellare un costrutto che contiene un'etichetta
   annidata: cancellava CODICE VIVO.

### Cosa ha trovato la sessione, oltre alle correzioni

* tre commenti nel sorgente che dicevano il falso (fra cui un gate dichiarato
  spento che era acceso);
* un test committato che contraddiceva il codice committato;
* quattro difetti nelle MIE misure, ognuno dei quali aveva prima prodotto un
  numero sbagliato pubblicato in chiaro.

## 67.5 Fronti aperti

* **423 chiamate in regioni irraggiungibili**, ora concentrate in Go e C#, in
  parte over-scan di `.pdata` (§63) e in parte difetto vero;
* **+628 `goto`** da riassorbire: l'obiettivo dichiarato e' ZERO;
* `var_tmp*` e `flag_` residui, che richiedono GVN e fusione di combinazioni;
* le voci della lista utente ancora intatte: `analysis-fn` per prologo/epilogo,
  `MlilCallAnalysis`/`ParameterTypeInference` per le firme, `flirt-apply` per i
  nomi.

---

# Round 68 — 2026-08-18 — Tre fronti chiusi come GIA' VINTI, e una scoperta che cambia le priorita'

## 68.1 `goto`: gia' all'ottimo misurato, non e' un fronte aperto

Sonda `RUSTRE_DBG_GOTO` su sample10_cs (4758 salti):

| classe | n | |
|---|---|---|
| `backward_plain` | 2399 | 50% |
| `forward_plain` | 2199 | 46% |
| `loop_backedge` | 144 | |
| `irreducible` | 13 | |

Solo **276 hanno `preds=1`** (bersaglio a un solo predecessore, quindi
riordinabile); 1615 hanno un bersaglio di 1-2 statement, quindi duplicabile.

Sonda `RUSTRE_DBG_DUP` sui rifiuti della duplicazione (le due voci
`branch_other_*` sono propagazioni ricorsive, le foglie sono le altre):

| causa | n |
|---|---|
| **`budget`** | **1247** |
| `loop_header` | 1169 |
| `scc` / `switch` / `cycle` | 47 |

`budget` NON e' un difetto: il cap e' gia' tarato su una curva misurata da una
sessione precedente — 2 e' il ginocchio (3,1 righe per goto rimosso), a 4 il
costo marginale e' 26,3, peggio dello structuring. `loop_header` e' un rifiuto
di CORRETTEZZA (copiare un header biforca il ciclo).

**Conclusione: la duplicazione di coda ha gia' dato tutto.** I 4600 salti
«semplici» residui hanno bersagli a piu' predecessori e richiedono structuring
per regioni, non duplicazione. Non e' un intervento da un round.

## 68.2 Nomi: path B e' AVANTI, e `flirt-apply` e' GIA' CABLATO

| | nomi veri | anonimi |
|---|---|---|
| path B | **5238** | 6104 (`fn_HEX`) |
| path A | 5124 | 6218 (`sub_HEX`) |

Path B ne ha **114 in piu'**. E `rustre-flirt-apply` risulta gia' usato da
`binary_entry.rs` (`FlirtScanner`, `flirt_pairs_for_load`,
`baseline_flirt_scanner`, `non_rust_flirt_scanner`, caricamento dei `.sig`).
La voce «flirt-apply per i nomi» della lista utente **e' chiusa**.

## 68.3 Riferimenti pendenti: path B e' AVANTI di piu' del doppio

| | nomi HEX usati | mai definiti | |
|---|---|---|---|
| path A | 8798 | **2900** | 33% |
| path B | 6718 | **931** | **14%** |

Di quei 931, solo **11** sono pura incoerenza di grafia (`sub_X` chiamato,
`fn_X` definito allo stesso indirizzo); i restanti 756 `sub_` e 164 `fn_` sono
bersagli genuinamente non emessi (import, thunk). Difetto reale ma piccolo.

## 68.4 ⚠ LA SCOPERTA: misuravo una configurazione che nessuno usa

Verificato lo stato di default dei 18 gate della «configurazione estesa» usata
dal §55 in poi: **la maggior parte e' OPT-IN.** Solo `EXPR_SIMPLIFY`,
`GOTO_BREAK`, `RELOOP_MULTIEXIT` e `CFGLOOP` sono predefiniti.

Path B PREDEFINITO contro configurazione estesa, corpus intero:

| | goto | JUMPOUT | `var_tmp*` | `flag_` | **`var_sp`** | dati | righe |
|---|---|---|---|---|---|---|---|
| **vero predefinito** | 11266 | 1 | 45395 | 42039 | **134462** | 7943 | 1028886 |
| configurazione estesa | 9541 | 0 | 37203 | 36428 | **12** | 7943 | 922900 |

**`var_sp` 134462 contro 12.** Per difetto path B stampa ancora il prologo
simulato a mano (`var_sp = var_sp - 8; *(__int64 *)var_sp = …` ×8 per funzione),
che `RUSTRE_HLIL_NOPROLOGUE` — opt-in — elimina. E' la voce «analysis-fn per
prologo/epilogo» della lista utente: la capacita' c'e', e' spenta.

**Ogni contatore e' migliore o uguale** nella configurazione estesa; i dati
materializzati sono identici (7943).

### Perche' conta per l'obiettivo

«Path B unico» significa che il suo comportamento PREDEFINITO diventa la
produzione. Tutte le misure dei round 57-67 valgono per una configurazione che
va ATTIVATA. Il lavoro che segue e' promuovere i gate misurati buoni, uno
scaglione alla volta e con la stessa disciplina: `diff -rq` fra due miei
snapshot, comportamento, e nessun contatore peggiorato.

Comportamento del vero predefinito: misura lanciata, esito al prossimo giro.

---

# Round 69 — 2026-08-18 — `NOPROLOGUE` predefinito: −99230 righe. E un'interruzione da modifiche concorrenti

## 69.1 Comportamento del vero predefinito: identico

| | funzioni | AGREE | LINK_FAIL |
|---|---|---|---|
| vero predefinito | 63 | 15 (23,8%) | 4 |
| configurazione estesa | 63 | 15 (23,8%) | 4 |

`cmp_paths.py`: **19 su 19 identiche**. Promuovere i gate e' quindi neutro sul
comportamento e migliora ogni contatore testuale — la condizione che serviva
per procedere.

## 69.2 `RUSTRE_HLIL_NOPROLOGUE` -> DEFAULT-ON (#6780)

Misurato in **isolamento** (unico gate acceso oltre a `RUSTRE_HLIL`, corpus
intero, 11342 file per lato):

| | `var_sp` | righe | goto | JUMPOUT | `var_tmp*` | `flag_` | dati |
|---|---|---|---|---|---|---|---|
| vero predefinito | 134462 | 1028886 | 11266 | 1 | 45395 | 42039 | 7943 |
| **+`NOPROLOGUE`** | **0** | **929656** | 11266 | 1 | 45395 | 42039 | 7943 |

**Un solo contatore si muove, e va a ZERO.** −99230 righe (−9,6%), tutto il
resto identico byte per byte.

Il commento sul sito di chiamata descriveva gia' il difetto come «di
CORRETTEZZA: scrittura attraverso un puntatore mai inizializzato, 57% del
corpus» — e la passata che lo ripara era **opt-in**. E' la voce «analysis-fn per
prologo/epilogo» della lista utente.

Prove per differenza: `diff -rq` nuovo predefinito contro gate esplicito
**0 differenze**; `diff -rq` path A **0 differenze**.

Quattro gate ora predefiniti: `FLAGDCE`, `TEMPPROP`, `TOPTEST_BREAK`,
`NOPROLOGUE`.

## 69.3 ⚠ Interruzione: `lib.rs` modificato da un altro agente durante il giro

A meta' round `cargo test` ha smesso di compilare:

```
error: mismatched closing delimiter: `}`
  --> crates
ustre-decompiler\src\lib.rs:1678:20
```

Non e' codice mio: e' il lifting di `cmpxchg`, e il diff non committato di
`lib.rs` era passato da 52 righe (i miei commenti) a **239 inserimenti**.
`Some(InstrLift::Handled(Some(CfsStatement::Raw(format!(` apre cinque
delimitatori e `))));` ne chiudeva quattro.

Ho seguito la regola di CLAUDE.md («riprovare, poi applicare la correzione
banale se stabile-rotto»): riprovato, confermato rotto anche per la lib, e
tentata la parentesi mancante. **Le mie due sostituzioni non hanno agganciato
perche' il file cambiava a ogni tentativo** — fra una lettura e la successiva le
stringhe erano gia' diverse (era sparito un `)` spurio dentro il testo emesso).
Alla verifica successiva la build passava: l'ha chiusa l'altro agente.

Stato finale verificato: lib compila (1 warning, `ops` non usato, non mio), i
**quattro gate sono ancora default-ON**, `cargo test -p rustre-decompiler --lib`
**1337 passati, 0 falliti**.

### Conseguenza sui numeri

Gli snapshot `all_*`, `final`, `vero_def`, `solo_nopro` sono stati generati
PRIMA di quelle modifiche. Le cifre dei §68-69 restano valide come confronti
fra due miei snapshot coetanei — che e' l'unico uso che CLAUDE.md considera
lecito — ma **non descrivono piu' l'emissione corrente**. Vanno rigenerati
prima di pubblicare qualunque assoluto.

## 69.4 Il resto dei gate opt-in, da promuovere a scaglioni

Ancora opt-in e misurati buoni dentro la configurazione estesa: `ZFTEMP`,
`CMOVFOLD`, `C_GOTO_REMOVAL`, `TAILDUP`, `LOOPS_DELEGATE`, `NESTED_REDEF_GUARD`,
piu' `DEADTMP` e `DEDUPCAST` (default-ON gia' verificati come `!env(...)`).
Nessuno e' stato ancora isolato singolarmente: `NOPROLOGUE` lo e' stato, ed e'
il motivo per cui e' stato promosso per primo.

---

# Round 70 — 2026-08-18 — Firme: path B ha il 65% in meno di argomenti fantasma

## 70.1 `MlilCallAnalysis` e `ParameterTypeInference`: ZERO chiamanti

Le due voci «argomenti e firme» della lista utente:

| | dove | righe | test | chiamanti fuori dal proprio file |
|---|---|---|---|---|
| `MlilCallAnalysis` | `rustre-il-mlil/src/mlil_call_analysis.rs` | 947 | 17 | **0** |
| `ParameterTypeInference` | `rustre-analysis-type/src/type_propagation.rs` | — | — | **0** |

`mlil_call_analysis` e' `pub mod` e offre `CallSite` (con gli argomenti per
sito), `ArgumentMapping`, `ReturnValueTracking`, `IndirectCallResolver`,
`VirtualCallResolver`. Capacita' spenta, terza del suo genere in questa
sessione dopo `hlil_control_flow_recovery` e i 17 gate opt-in.

## 70.2 Prima di cablarla: quanto vale il premio?

`callsite_consistency.py` misura il difetto che quella crate indirizza — la
contraddizione fra l'arieta' con cui una funzione e' DEFINITA e quella con cui
e' CHIAMATA, dentro lo stesso progetto emesso, senza verita' esterna.

### ⚠ Due difetti nella misura, corretti prima di usarla

1. **Mescolava i due percorsi.** Raccoglieva tutti i `.c`, quindi confrontava la
   definizione di path A con le chiamate di path B. Mescolato dava
   **11903 OVER / 11490 UNDER**; filtrato su path A da' **9756 / 6041**, che
   combacia esattamente con la baseline in CLAUDE.md. Il numero mescolato era
   gonfiato del 22%.
2. **Non riconosceva le firme di path B.** `DEF_RE` esigeva `) {` sulla STESSA
   riga; path B mette la graffa su quella dopo. Su path B contava **0
   definizioni** — taceva invece di sbagliare, il che e' meglio, ma la rendeva
   inutilizzabile. Reso opzionale il `{`.

Controprova del rilassamento: i numeri di path A restano **identici**
(10330 / 9756 / 6041), quindi non ha introdotto falsi positivi.

## 70.3 Il risultato: parita' a favore di path B

| | definizioni | **OVER** | UNDER |
|---|---|---|---|
| path A | 10330 | **9756** | 6041 |
| path B | **11300** | **3421** | 6478 |

* **OVER −65%.** E' la classe PERICOLOSA: un argomento in piu' a un sito di
  chiamata compila pulito sotto le regole non prototipate di `gnu89` — la stessa
  cecita' che lasciava leggere 11143/11144 con 2233 parametri fantasma.
* UNDER +7%, cioe' path B manca qualche argomento in piu'. Meno grave: un
  argomento mancante e' un difetto visibile, uno di troppo e' silenzioso.
* Path B ispeziona **970 definizioni in piu'**.

### Conseguenza sulla priorita'

Cablare `MlilCallAnalysis` per «migliorare le firme di path B» avrebbe avuto
senso se path B fosse indietro. **Non lo e': e' avanti di due terzi sulla classe
peggiore.** Il premio non e' dove la lista lo colloca. Se quella crate va
cablata, il bersaglio giusto e' l'`UNDER` (6478) e la risoluzione delle chiamate
indirette, non l'`OVER`.

## 70.4 Quinta capacita' spenta trovata, e un bilancio

Fin qui, in questa sessione: `hlil_control_flow_recovery` (981 righe, 7 test, 0
chiamanti), `MlilCallAnalysis` (947, 17, 0), `ParameterTypeInference` (0
chiamanti), 17 gate opt-in fra cui uno che valeva 99230 righe, e
`published_lib_arity` dietro un gate spento (gia' noto da CLAUDE.md).

Il quadro e' coerente con la diagnosi generale: **il decompilatore non manca di
capacita', le tiene spente.**

## 70.5 In corso

Isolamento dei sei gate opt-in rimasti (`ZFTEMP`, `CMOVFOLD`, `C_GOTO_REMOVAL`,
`TAILDUP`, `LOOPS_DELEGATE`, `NESTED_REDEF_GUARD`), uno alla volta sul corpus
intero contro una base rigenerata col binario corrente. Tre su sette snapshot
pronti.

---

<!-- I round successivi si aggiungono qui sotto. Non rimuovere nulla di sopra. -->
