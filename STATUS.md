# RustRE — Stato del progetto

**Diagnosi misurata del workspace**

- Data della misura: **2026-08-18**
- Commit di riferimento: `193c7c0` + 953 righe non committate
- Metodo: ogni cifra in questo documento è stata **misurata** su questo albero, non dedotta da commenti, README o storia git. Dove una cifra è incerta, è scritto che lo è.

---

## Indice

- [0. Sintesi esecutiva](#0-sintesi-esecutiva)
- [1. Scala del workspace](#1-scala-del-workspace)
- [2. Copertura della specifica](#2-copertura-della-specifica-infotxt)
- [3. Il difetto architetturale principale: il grafo è piatto](#3-il-difetto-architetturale-principale-il-grafo-è-piatto)
- [4. Distribuzione delle dimensioni: crescita non organica](#4-distribuzione-delle-dimensioni-crescita-non-organica)
- [5. Codice morto e codice non cablato](#5-codice-morto-e-codice-non-cablato)
- [6. Il pattern degli stub: codice che mente invece di fallire](#6-il-pattern-degli-stub-codice-che-mente-invece-di-fallire)
- [7. Mismatch fra documentazione e misure](#7-mismatch-fra-documentazione-e-misure)
- [8. Il decompilatore: l'unica parte integrata](#8-il-decompilatore-lunica-parte-integrata)
- [9. Igiene del repository](#9-igiene-del-repository)
- [10. Piano di lavoro](#10-piano-di-lavoro)
- [Appendice A — Tabella completa delle 190 crate](#appendice-a--tabella-completa-delle-190-crate)
- [Appendice B — Metodologia di misura](#appendice-b--metodologia-di-misura)

---

## 0. Sintesi esecutiva

In una frase:

> **Un decompilatore reale e misurabile (~81k righe, 24 dipendenze integrate, 5 metriche indipendenti) circondato da 3,7M righe di libreria pure-Rust larga quanto la specifica ma piatta, con tutte le capacità FFI-dipendenti rimosse e circa 8.000 punti di mock che non falliscono.**

Le cinque conclusioni che contano:

| # | Conclusione | Evidenza |
|---|---|---|
| 1 | **Il workspace compila pulito.** A questa scala non è scontato e va detto per primo. | `cargo check --workspace --release --all-targets` → exit 0 in 2m23s |
| 2 | **La larghezza della specifica è coperta, la profondità no.** | 186 crate promesse in `info.txt` §1.3, 190 presenti; ma 15 cancellate — tutte e sole quelle con dipendenza nativa |
| 3 | **Le crate non compongono.** Sono foglie appese a `rustre-core`, cablate solo dentro un wrapper MCP. | `rustre-core` 84 dipendenti, ogni altra ≤ 11; `rustre-mcp-tools` dipende da 186 crate |
| 4 | **Il codice, dove è incompleto, restituisce dati plausibili invece di fallire.** | ~8.000 occorrenze di stub/mock/placeholder contro **1** `todo!()` e **0** `unimplemented!()` |
| 5 | **`CLAUDE.md` è disallineato dalle misure in `runs/`.** Quattro numeri su cui si basa ogni sessione futura sono falsi. | Confronto §7 |

---

## 1. Scala del workspace

| Metrica | Valore |
|---|---|
| Crate nel workspace | **190** |
| Membri commentati in `Cargo.toml` | 16 |
| File `.rs` | 4.092 |
| Righe di Rust | **3.844.847** |
| Byte di Rust | 142.096.297 (≈ 142 MB) |
| Funzioni `#[test]` | **104.438** |
| Blocchi `#[cfg(test)]` | 2.823 |
| Righe dentro `mod tests` | ≈ 1.061.263 (**27,6%**) |
| Righe di produzione (stimate) | ≈ 2.783.584 |
| Attributi `#[allow(...)]` | 382 |
| Esito `cargo check --workspace --release --all-targets` | **exit 0**, 2m23s |

### 1.1 Lettura

3,84M righe con 104k test che compilano puliti è, in termini assoluti, un risultato di ingegneria non banale. Il problema non è la quantità né la correttezza sintattica: è **come quella massa è distribuita** (§4) e **quanto di essa è raggiungibile** (§3).

Il rapporto test/produzione (27,6%) è sano su carta. §4 spiega perché in pratica non lo è: i test coprono la superficie delle API, non l'integrazione fra crate — perché quell'integrazione, in larga parte, non esiste.

---

## 2. Copertura della specifica (`info.txt`)

`info.txt` è la specifica di progetto: **7.135 righe, 37 sezioni**, dalla teoria della decompilazione (Cifuentes 1994, Phoenix, DREAM) fino al frontend GPUI e all'orchestrazione MCP.

L'albero del workspace in §1.3 elenca **186 crate**. Nel repository ce ne sono **190**.

### 2.1 Le 15 crate della specifica che non esistono

```
rustre-debug-frida      rustre-debug-gdb       rustre-debug-kgdb
rustre-debug-linux      rustre-debug-macos     rustre-debug-unicorn
rustre-debug-windbg     rustre-debug-windows   rustre-decompiler-ghidra
rustre-emu-qiling       rustre-emu-unicorn     rustre-symb-z3
rustre-gui-docking      rustre-gui-themes      rustre-gui-views
```

Sono commentate in `Cargo.toml` con una motivazione datata 2026-07-12 (eliminazione di dipendenze native auto-scaricanti) e le directory sono state rimosse.

**Non è un elenco casuale: è esattamente e soltanto l'insieme delle crate che richiedevano una dipendenza nativa esterna.**

### 2.2 Conseguenze verificate, non ipotizzate

**§13 — Symbolic execution & taint analysis.**
`rustre-symb-engine` espone `to_smtlib2()`, `to_smtlib2_script()`, e test come `state_smtlib2_has_check_sat`. Sa **formattare** il problema in SMT-LIB2. Non esiste nessun solver che lo risolva: `z3-sys` non compare in nessun `Cargo.toml` del workspace. La symbolic execution promessa dalla specifica è oggi un **serializzatore di vincoli**.

**§12 — Emulation.**
`rustre-emu` non usa Unicorn. Ha interpreti scritti a mano: `step_thumb16`, `step_thumb32`, `step_x86_arith`, `step_x86_cmp`. L'emulazione copre l'insieme di istruzioni che qualcuno ha avuto tempo di implementare a mano — non l'ISA completa che Unicorn avrebbe dato.

**§9/§11 — Debugger e instrumentation.**
Nessun backend per sistema operativo, nessun Frida. Tutto riassorbito in `rustre-debug`, che con **133.279 righe** è la crate più grande del workspace.

**§32 — Frontend GPUI.**
Nessuna separazione views/docking/themes: `rustre-gui` è un monolite da **127.122 righe** con **0 dipendenti**.

### 2.3 Dipendenze native effettivamente presenti

Conteggio su tutti i `Cargo.toml` delle crate:

| Dipendenza | Crate che la usano |
|---|---|
| `tokio` | 58 |
| `petgraph` | 24 |
| `rusqlite` | 23 |
| `goblin` | 9 |
| `iced-x86` | 5 |
| `capstone` | 2 |
| `pyo3` | 2 |
| `mlua` | 2 |
| `yara-x` | 1 |
| `gpui` | 1 |
| `gimli` | 1 |
| `unicorn-engine` | **0** |
| `z3-sys` | **0** |
| `frida-*` | **0** |

### 2.4 Giudizio

La scelta pure-Rust è **difendibile**: build riproducibili, nessun download nativo, portabilità. Il difetto non è la scelta — è che **non è stata propagata alla specifica**. Oggi `info.txt` §11, §12 e §13 promettono capacità che il codice simula. Questa è la sorgente strutturale della classe di mismatch descritta in §6 e §7.

### 2.5 Le 20 crate presenti ma non previste

```
rustre-adb                rustre-analysis-typerecov  rustre-arch-registry
rustre-db                 rustre-il                  rustre-knowledge
rustre-loader-registry    rustre-mobile              rustre-patch
rustre-plugin-api         rustre-plugin-host         rustre-plugin-loader
rustre-plugin-lua         rustre-plugin-native       rustre-plugin-python
rustre-project            rustre-ti-opencti          rustre-ti-otx
rustre-ti-shodan          rustre-ttd-replayer
```

Molte sono legittime (il sottosistema plugin, `rustre-knowledge`/`rustre-db`/`rustre-project` che realizzano P4). Quattro di esse sono però gusci vuoti — vedi §3.2.

---

## 3. Il difetto architetturale principale: il grafo è piatto

Ho costruito il grafo delle dipendenze inverse fra le 190 crate (chi dipende da chi, leggendo ogni `Cargo.toml`).

### 3.1 La forma del grafo

| Crate | Dipendenti |
|---|---|
| `rustre-core` | **84** |
| `rustre-deobf` | 11 |
| `rustre-analysis` | 11 |
| `rustre-il-llil` | 9 |
| `rustre-loader-pe` | 8 |
| `rustre-threatintel` | 8 |
| `rustre-symbols`, `rustre-triage`, `rustre-net`, `rustre-pe-tools`, `rustre-demangle`, `rustre-flirt-apply` | 7 |
| *tutte le altre* | ≤ 6 |

E il dato che chiude il discorso:

> **`rustre-mcp-tools` dipende da 186 crate su 190.**

Questo descrive una topologia a stella, non una pipeline. I principi **P1** (plugin everywhere, registry di trait) e **P2** (IR multi-livello LLIL→MLIL→HLIL) della specifica descrivono una **catena di composizione**: loader → arch → IR → analysis → decompiler. Nel repository quella catena esiste **in un punto solo**.

### 3.2 Il collo di bottiglia: i registry sono gusci

I registry sono l'infrastruttura che P1 rende non negoziabile — sono il punto in cui un loader o un'architettura si registra e diventa raggiungibile dal resto della pipeline. Misura:

| Crate | Righe | Dipendenti | Ruolo secondo la specifica |
|---|---|---|---|
| `rustre-il` | 152 | 6 | facciata unificante sopra LLIL/MLIL/HLIL |
| `rustre-loader-registry` | 215 | **0** | registry dei loader (P1) |
| `rustre-arch-registry` | 77 | **0** | registry delle architetture (P1) |
| `rustre-mobile` | 43 | **0** | facciata del sottosistema mobile |

Due dei quattro registry hanno **zero dipendenti**: nessuno li usa, quindi nessun loader e nessuna architettura si registra da nessuna parte. Ogni crate `rustre-loader-*` e `rustre-arch-*` è raggiungibile solo per path diretto — cioè, in pratica, solo dal wrapper MCP.

**Questa è la causa meccanica della piattezza del grafo.** Finché i registry restano vuoti, ogni nuova crate nasce foglia, e P1 rimane un principio scritto e non implementato.

### 3.3 L'eccezione: il decompilatore

`rustre-decompiler` dipende da **24 crate reali**:

```
rustre-core              rustre-decompiler-cfs    rustre-decompiler-c
rustre-decompiler-type   rustre-decompiler-expr   rustre-analysis-typerecov
rustre-analysis-type     rustre-analysis-fn       rustre-analysis-callconv
rustre-analysis-dataflow rustre-analysis-cfg      rustre-analysis-vsa
rustre-analysis-xref     rustre-analysis-vtable (opt)
rustre-loader            rustre-symbols-pdb       rustre-arch-x86
rustre-il   rustre-il-llil   rustre-il-mlil   rustre-il-hlil   rustre-il-passes
rustre-flirt-apply       rustre-demangle
```

Questo **è** la pipeline P1/P2. È l'unica parte del progetto veramente integrata, ed è — non a caso — **l'unica con metriche misurate su corpus reale** (§8). La correlazione fra "integrato" e "misurabile" non è accidentale: si può misurare solo ciò che si può eseguire end-to-end.

---

## 4. Distribuzione delle dimensioni: crescita non organica

### 4.1 Il dato

| Fascia | Numero di crate |
|---|---|
| < 1.000 righe | 4 |
| 1.000 – 5.000 | 7 |
| 5.000 – 15.000 | 4 |
| **15.000 – 22.000** | **153** |
| > 22.000 | 22 |

**153 crate su 190 — l'81% — stanno dentro una banda larga 7.000 righe.**

### 4.2 Perché è un'anomalia

Un workspace cresciuto organicamente ha una distribuzione a coda lunga: molte crate piccole (un parser, un tipo, un adattatore), poche grandi. Qui la distribuzione è **bimodale con un picco artificiale**: 22 crate reali di dimensione variabile (`rustre-debug` 133k, `rustre-gui` 127k, `rustre-il-lift` 91k, `rustre-decompiler` 81k, `rustre-demangle` 53k, `rustre-arch-x86` 44k) e un plateau di 153 crate tutte a ~17k.

La lettura più semplice, coerente con il 27,6% di righe-test e i 104.438 test: **molte crate sono state portate a una taglia-obiettivo scrivendo test su API poco profonde**. I test esistono e passano, ma verificano la **superficie** delle funzioni, non la loro composizione — perché, come stabilito in §3, quella composizione in larga parte non c'è.

### 4.3 Implicazione operativa

Il numero "104.438 test verdi" **non è un segnale di qualità utilizzabile**. Non distingue un'implementazione corretta da un placeholder che restituisce un valore plausibile (§6). Questo è precisamente l'errore che il progetto ha già commesso e documentato altrove: una regressione che inventò 2.233 parametri fantasma lasciò la metrica di ricompilabilità a 11143/11144 mentre la fedeltà crollava.

**Regola che ne discende:** nessun cambiamento in questo repository va giudicato su un conteggio di test verdi. Serve una metrica che possa fallire.

---

## 5. Codice morto e codice non cablato

### 5.1 Le 19 crate orfane (zero dipendenti)

| Crate | Righe | Note |
|---|---|---|
| `rustre-gui` | 127.122 | binario finale — orfano legittimo |
| `rustre-bin` | 16.724 | binario — legittimo |
| `rustre-cli` | — | binario — legittimo |
| `rustre-daemon` | — | binario — legittimo |
| `rustre-mcp` | — | binario MCP — legittimo |
| `rustre-crypto-oracle` | ~17k | **funzionalità non cablata** |
| `rustre-crypto-whitebox` | ~17k | **funzionalità non cablata** |
| `rustre-symb-taint` | ~17k | **funzionalità non cablata** |
| `rustre-symbols-codeview` | ~17k | **funzionalità non cablata** |
| `rustre-ti-correlate` | ~17k | **funzionalità non cablata** |
| `rustre-ti-shodan` | 2.398 | **funzionalità non cablata** |
| `rustre-triage-yara` | ~17k | **funzionalità non cablata** |
| `rustre-emu-shellcode` | 16.759 | **funzionalità non cablata** |
| `rustre-sandbox-extract` | ~16k | **funzionalità non cablata** |
| `rustre-sandbox-monitor` | ~16k | **funzionalità non cablata** |
| `rustre-plugin-host` | ~17k | **funzionalità non cablata** |
| `rustre-plugin-loader` | ~17k | **funzionalità non cablata** |
| `rustre-arch-registry` | 77 | **registry vuoto — vedi §3.2** |
| `rustre-loader-registry` | 215 | **registry vuoto — vedi §3.2** |

Cinque sono binari, quindi orfani per definizione. **Le altre quattordici sono funzionalità scritta e mai collegata.**

Notevole: `rustre-symbols-codeview` è orfana, ma `rustre-debug` contiene un proprio `codeview/codeview_parser.rs`. Due implementazioni dello stesso formato, una raggiungibile e una no.

### 5.2 Gli attributi `#[allow(...)]`

382 in totale. Ripartizione:

| Attributo | Occorrenze |
|---|---|
| `#[allow(unused_imports)]` | 174 |
| `#![allow(dead_code)]` | 39 |
| `#[allow(dead_code)]` | 28 |
| `#[allow(clippy::cast_possible_truncation)]` | 21 |
| `#[allow(clippy::cast_precision_loss)]` | 15 |
| `#[allow(clippy::too_many_lines)]` | 13 (+8 a livello crate) |
| `#![allow(unused_imports, dead_code)]` | 5 |
| `#[allow(non_snake_case)]` | 5 |
| `#[allow(clippy::too_many_arguments)]` | 5 |
| `#![allow(dead_code, unused_variables)]` | 2 |
| `#[allow(unsafe_code)]` | 2 |
| `#![allow(unsafe_code, reason = "…")]` | 2 |
| altri (clippy vari) | ~60 |

I ~74 `allow(dead_code)` e i ~179 `allow(unused_imports)` **non sono rumore stilistico**: in questo workspace il dead code è funzionalità scollegata (§5.1), quindi ognuno di quegli attributi nasconde un punto di cablaggio mancante.

### 5.3 Difetti veri emersi dai warning di compilazione

`cargo check --workspace --release --all-targets` produce 196 warning in `rustre-mcp-tools`. Non sono tutti cosmetici. Tre classi sono difetti reali:

**a) Circa 25 tool SPARC scritti e mai registrati.**

```
wire_tools.rs:29723  struct SparcEncodeNopWireTool is never constructed
wire_tools.rs:29754  struct SparcEncodeCallWireTool is never constructed
wire_tools.rs:29851  struct SparcEncodeSethiWireTool is never constructed
wire_tools.rs:29856  struct SparcEncodeAluRegWireTool is never constructed
...  (Store, Jmpl, SynthMovImm, SynthMovReg, SynthClr, SynthNeg, SynthNot,
     BuildPrologue, BuildEpilogue, LookupV8Trap, LookupAsi, LookupCondition,
     ExtractBranchTargets, EncodeBicc, SynthTst, SynthCmpReg, SynthCmpImm,
     SynthInc, SynthDec, SynthSet, BuildReturnSeq, LookupV9Trap,
     LookupFpOpcode, LookupPrivReg)
wire_tools.rs:29802  fn sparc_arg_u32 is never used
wire_tools.rs:29807  fn sparc_arg_i32 is never used
wire_tools.rs:29812  fn sparc_arg_u8  is never used
```

L'intera superficie SPARC del server MCP esiste, compila, ed è **irraggiungibile**. È l'esatto opposto di codice morto da cancellare: è codice vivo mai collegato.

**b) Due funzioni di registrazione handler mai chiamate.**

```
decompiler_type_extra.rs:280  fn push_decompiler_type_extra_handlers is never used
dataflow_extra.rs:389         fn dataflow_extra_handlers            is never used
```

Non sono singoli tool: sono le funzioni che ne registrano **interi gruppi**. Ogni tool che dipende da loro è irraggiungibile.

**c) Varie.**

```
lib.rs:602                       fn detect_packers is never used
linux_debug.rs:206,276,335,442   unused variable: `args`   (x4)
```

I quattro `args` inutilizzati in `linux_debug.rs` meritano attenzione: una funzione che accetta argomenti e non li legge è, quasi per definizione, un handler che ignora la richiesta e restituisce una risposta fissa.

---

## 6. Il pattern degli stub: codice che mente invece di fallire

### 6.1 Il dato

Conteggio di occorrenze su tutte le crate:

| Marcatore | Occorrenze |
|---|---|
| `stub` / `Stub` | **4.340** |
| `mock` / `Mock` | **3.600** |
| `simplified` | 1.049 |
| `placeholder` | 704 |
| `for now` | 68 |
| `not implemented` | 40 |
| `TODO` | 38 |
| `in a real` | 27 |
| `FIXME` | 3 |
| **`todo!()`** | **1** |
| **`unimplemented!()`** | **0** |

### 6.2 Perché questo rapporto è la diagnosi

Ci sono **circa 8.000 punti dove il codice è dichiaratamente incompleto e 1 solo punto dove lo ammette a runtime.**

La differenza è tutta:

- `todo!()` **esplode**. Un test che lo attraversa fallisce. Un utente che lo raggiunge riceve un errore. L'incompletezza è **visibile**.
- Un mock **restituisce un valore plausibile**. Il test passa. L'utente riceve un risultato che sembra un'analisi. L'incompletezza è **invisibile**.

Con 104.438 test verdi sopra (§4.3), la copertura non può rilevare la differenza. **Questo codice, dove è incompleto, mente invece di fallire** — che è la peggiore combinazione possibile per uno strumento di reverse engineering, dove l'output è per definizione difficile da validare a occhio.

### 6.3 Crate a più alta densità

Occorrenze per 1.000 righe, crate sopra le 500 righe:

| Crate | Densità | Hit | Righe |
|---|---|---|---|
| `rustre-plugin-python` | 18,9 | 58 | 3.067 |
| `rustre-script-python` | 18,0 | 337 | 18.740 |
| `rustre-deobf-mba` | 15,5 | 258 | 16.685 |
| `rustre-emu-shellcode` | 15,2 | 255 | 16.759 |
| `rustre-sandbox-report` | 11,5 | 199 | 17.289 |
| `rustre-mcp-server` | 10,6 | 203 | 19.078 |
| `rustre-mobile-jadx` | 9,7 | 181 | 18.689 |
| `rustre-emu` | 9,3 | 183 | 19.758 |
| `rustre-mobile-ios` | 9,2 | 172 | 18.714 |
| `rustre-mobile-dyld` | 9,1 | 174 | 19.106 |
| `rustre-syscalls-windows` | 8,5 | 166 | 19.545 |
| `rustre-syscalls` | 7,8 | 135 | 17.344 |
| `rustre-arch` | 7,3 | 125 | 17.076 |
| `rustre-debug` | 7,0 | **929** | 133.279 |
| `rustre-plugin-api` | 6,6 | 127 | 19.353 |
| `rustre-loader-elf` | 6,4 | 143 | 22.393 |
| `rustre-mcp-tools` | 5,4 | **703** | 129.535 |

In valore assoluto i due maggiori accumuli sono `rustre-debug` (929) e `rustre-mcp-tools` (703) — le due crate più grandi dopo la GUI, e le due più esposte all'utente.

### 6.4 Correlazione con §2.4

Le crate a densità più alta sono in larga parte **proprio quelle orfane della decisione pure-Rust**: `emu-shellcode` e `emu` (niente Unicorn), `plugin-python`/`script-python` (pyo3 presente ma limitato), `mobile-jadx`/`mobile-dyld`/`mobile-ios` (niente tooling esterno). Il mock non è nato per pigrizia: è **il residuo lasciato dalla rimozione delle dipendenze native**. Correggere §2.4 e correggere §6 sono lo stesso lavoro.

---

## 7. Mismatch fra documentazione e misure

Questo è il punto più urgente sul piano operativo, perché `CLAUDE.md` è il contesto caricato in **ogni** sessione futura: un suo numero falso si propaga a ogni decisione successiva.

### 7.1 Il confronto

| Affermazione in `CLAUDE.md` | Misura in `runs/wip_0815/metrics.json` (2026-08-15) | Verdetto |
|---|---|---|
| behaviour baseline **7/14** | `behaviour_tested: 63`, `behaviour_agree: 15` | **obsoleto** — il denominatore è cambiato |
| path A definisce **ZERO** data symbol | `data_symbols_defined: 5427` | **falso** |
| `unresolved_actionable` **7329** | `unresolved_actionable: 4012` | **obsoleto** |
| arity legacy **15/16** | `arity_fidelity_legacy: 14/16` | **possibile regressione** |
| `unresolved_code_as_data` = 0 (classe `apply` chiusa) | `unresolved_code_as_data: 0` | **confermato** |
| `arity_correct` 122/135, 6 over / 7 under | 122/135, 6 over, 7 under | **confermato** |
| `crossbuild_inconsistent` 2 | `crossbuild_inconsistent: 0` (su 1619 confronti) | **migliorato** |
| `duplicate_param` 4 | 4 | **confermato** |

### 7.2 Cosa ne discende

**a) Il diff non committato è lavoro di valore, misurato e non salvato.**

Le 953 righe non committate (`lib.rs` +353, `binary_entry.rs` +126, `batch_decompiler.rs` +94, e altri) sono il **port di `data_symbol_definitions` da path B a path A** che `CLAUDE.md` indica come "il lavoro da fare". È fatto e funziona:

| Metrica | `b_switch_final` (23/07) | `wip_0815` (15/08) | Δ |
|---|---|---|---|
| `data_symbols_defined` | 0 | **5.427** | +5.427 |
| `unresolved_actionable` | 6.653 | **4.012** | −2.641 |
| `unresolved_files` | 5.449 | **4.717** | −732 |
| `crossbuild_inconsistent` | 2 | **0** | −2 |
| `c_files` | 11.144 | 11.342 | +198 |

Questa è la cosa di maggior valore attualmente **non protetta da un commit**.

**b) `arity_fidelity_legacy` è sceso 15/16 → 14/16.**

Non è concludente: entrambi i run sono marcati `tainted: true` e hanno `harness_fingerprint` diverso (`0751a2ad…` vs `7eaf8b78…`), quindi il confronto ricade nella categoria `changed (harness differs)` che `measure.sh` per progetto non conteggia come regressione. **Ma è esattamente il caso che le regole di questo repository dicono di non archiviare come rumore.** A n=16 una funzione vale 6,25%: segnale e rumore hanno la stessa ampiezza. Va risolto ri-misurando con harness identico, non discusso.

### 7.3 Un run è in corso

`tests/decompiler_corpus/runs/base_0818/` è datato **oggi**, contiene `arity.json`, `arity.txt`, `behavior.txt`, `braces.txt`, `fidelity.txt` e una directory `out/` con **12 file**, ma **nessun `metrics.json`**.

Due letture possibili: un altro agente sta misurando in questo momento, oppure il run è abortito prima di consolidare. In entrambi i casi:

> **Nessun numero assoluto va pubblicato finché quel run non chiude.** `out/` non è un oracolo — è condiviso fra agenti concorrenti e può essere sovrascritto a metà verifica.

I parziali già scritti concordano con `wip_0815` sull'arità: `correct arity: 122 (90,4%)`, `OVER 6`, `UNDER 7`.

---

## 8. Il decompilatore: l'unica parte integrata

### 8.1 Perché merita una sezione a sé

È l'unica parte del progetto che soddisfa tutte e tre queste condizioni:

1. **Compone** — 24 dipendenze reali, la pipeline P1/P2 vera (§3.3).
2. **È misurata** — cinque metriche indipendenti con oracoli diversi.
3. **Le sue metriche possono fallire** — cosa che i 104k test unitari non possono fare (§4.3).

### 8.2 Le cinque metriche e cosa ciascuna vede

| Metrica | Oracolo | Cosa cattura | Cosa **non** cattura |
|---|---|---|---|
| **Ricompilabilità** (`check.sh`) | `gcc -std=gnu89 -fsyntax-only` | validità sintattica e di tipo | l'essere *sicuri di sé e sbagliati*: i parametri fantasma compilano perfettamente |
| **Arità** (`fidelity_arity.py`, 135 prototipi) | prototipi pubblicati mingw-w64/libgcc | errore **uniforme** di firma | errore non uniforme; e non vede oltre la firma |
| **Cross-build** (`cross_build.py`, 1.619 confronti) | il corpus come gruppo di controllo di sé stesso | errore **non uniforme** fra build | errore uniforme: `_Unwind_FindEnclosingFunction` è coerentemente sbagliata in ogni build |
| **Comportamento** (`behavior.py`) | esecuzione affiancata all'originale | l'obiettivo dichiarato, non un proxy | solo 63 funzioni su ~11k sono testabili |
| **Simboli irrisolti** (`unresolved.py`) | sezioni PE del binario | linkabilità reale | nulla sulla correttezza semantica |

Le metriche di arità e cross-build sono **complementari per costruzione**: nessuna delle due vede ciò che vede l'altra. Questa è la ragione per cui devono essere lette insieme, ed è il modello da estendere al resto del progetto.

### 8.3 Perché `behavior.py` conta anche a 15/63

Perché è l'unica che misura l'obiettivo (codice che *fa* la stessa cosa) invece di un proxy (codice che *compila*). L'esempio già documentato: `count_set_flags` ottiene un punteggio di confidenza **92 "(no signals)"**, compila pulito, e legge **32 byte oltre la fine di ogni elemento**. Sia `check.sh` sia il punteggio di confidenza sono strutturalmente ciechi a quel difetto. Solo eseguire il codice lo trova.

### 8.4 Il fronte aperto

`unresolved_actionable: 4.012` su `runs/wip_0815`. Dopo il port dei data symbol (§7.2a) restano ~4.000 riferimenti a dati reali nell'immagine che l'emettitore potrebbe materializzare e non materializza. Con `unresolved_files: 4.717` su 11.342, circa il **41,6% dei file non può linkare**.

Distinzione da tenere presente e già verificata sul campo: **aggiungere una dichiarazione alza la ricompilabilità e non può muovere la linkabilità. Solo una definizione può.**

---

## 9. Igiene del repository

### 9.1 `tools/` — 122 MB di archivi

| File | Dimensione |
|---|---|
| `Themida_3.2.4.52_x32_x64.zip` | 65 MB |
| `Code_Virtualizer_x32_x64_v3.2.3.0.zip` | 32 MB |
| `CobaltStrike Source Code.zip` | 25 MB |
| `gen_runtime_prototypes.py` | 12 KB |

Gli ZIP sono coperti da `.gitignore:55` (`tools/*.zip`), quindi **non entrano nella storia git** — il rischio immediato è scongiurato. Restano due raccomandazioni: tenerli fuori da qualunque archivio o pacchetto distribuibile, e valutare se `tools/` sia il posto giusto per campioni di protettori commerciali e sorgenti di un framework C2 (meglio una directory esterna al repository, referenziata).

`gen_runtime_prototypes.py` è invece uno strumento del progetto e va **tracciato**.

### 9.2 `RULES.md` non tracciato

`crates/rustre-decompiler/RULES.md` ricostruisce l'elenco delle "REGOLA #N" citate per numero nel sorgente e **mai esistite come file** (verificato: assenti da `crates/`, da `docs/` e dalla storia git). La ricostruzione è fatta con provenienza riga per riga e dichiara esplicitamente dove l'enunciato non è deducibile, invece di inventarlo.

È esattamente il tipo di documento che questo progetto ha bisogno di preservare. **Va committato.**

### 9.3 Membri commentati che puntano a directory rimosse

I 16 membri commentati in `Cargo.toml` (§2.1) referenziano path che non esistono più. Innocuo per la build (sono commenti), ma è un'informazione che va spostata dove è leggibile: un commento nel manifest non è una decisione architetturale documentata. Vedi §10, punto 5.

---

## 10. Piano di lavoro

In ordine di rapporto valore/rischio.

### 1. Committare il diff da 953 righe

Lavoro misurato, funzionante, non protetto. Rischio: perdita. Costo: minuti. → §7.2a

### 2. Chiudere/ri-lanciare `base_0818` e ri-baselinare, poi aggiornare `CLAUDE.md`

Quattro numeri su cui si basa ogni sessione futura sono falsi. Finché non sono corretti, ogni decisione parte da premesse sbagliate. → §7.1, §7.3

### 3. Cablare il codice morto invece di silenziarlo

I ~25 tool SPARC, i due `*_handlers` mai chiamati, `detect_packers`, i quattro `args` ignorati. Fix meccanico, guadagno immediato, zero rischio di regressione semantica.

**Vincolo:** non cancellare — *aggiungere* il collegamento mancante. In questo workspace il dead code è funzionalità scollegata, non scarto. → §5.3

### 4. Riempire i 4 registry

`rustre-il`, `rustre-arch-registry`, `rustre-loader-registry`, `rustre-mobile`. È il collo di bottiglia che tiene il grafo piatto: senza di essi P1 non esiste e ogni nuova crate nasce foglia. Questo è l'unico intervento della lista che cambia la **forma** del progetto invece del suo contenuto. → §3.2

### 5. Decidere esplicitamente su Z3 e Unicorn

Due opzioni oneste, entrambe accettabili; la terza — lo stato attuale — no:

- **(a)** reintrodurli come *feature* opzionale, non di default, così la build pure-Rust resta;
- **(b)** riscrivere `info.txt` §11/§12/§13 per dichiarare cosa esiste davvero.

Lo stato presente — specifica che promette, codice che simula — è la **sorgente strutturale** della classe di mismatch di §6 e §7. → §2.2, §2.4, §6.4

### 6. Rendere visibile l'incompletezza dei mock

Nelle crate a densità più alta (§6.3), sostituire il mock silenzioso con un fallimento esplicito. Rompe dei test — **ed è il punto**: meglio un rosso onesto che 104k verdi che non distinguono un'implementazione da un placeholder.

**Attenzione al conflitto di regole.** Questo è l'unico punto della lista che *rimuove* comportamento, ed è in tensione con la regola "il dead code va cablato, non cancellato" e con "aggiungere codice, non toglierlo". Va quindi eseguito in forma additiva:

1. produrre prima l'**inventario** dei punti di mock (crate, file, riga, cosa dovrebbe fare);
2. marcarli in modo **rilevabile a compilazione**, non cancellarli;
3. convertire in `todo!()` **solo** i punti per cui l'inventario prova che non esiste implementazione sottostante — mai quelli dove il mock è un fallback legittimo.

→ §6

---

## Regola di build

> **Si builda e si testa esclusivamente in release.**
>
> ```
> cargo build   --release -p <crate>
> cargo test    --release -p <crate> --lib
> cargo check   --workspace --release --all-targets
> ```
>
> Mai build di debug. Dopo ogni modifica, ricompilare **prima** di rigenerare il corpus, e verificare l'`mtime` del binario: una corsa fra build ed edit concorrenti può lasciare un binario stale, e un binario stale produce numeri che sembrano validi.

---

## Appendice A — Tabella completa delle 190 crate

Colonne: righe totali (test inclusi) · funzioni `#[test]` · numero di crate che dipendono da questa · occorrenze di marcatori stub/mock/placeholder/simplified/todo.

| Crate | Righe | Test | Dipendenti | Stub-hit |
|---|---:|---:|---:|---:|
| `rustre-adb` | 18486 | 621 | 1 | 33 |
| `rustre-agent` | 17471 | 493 | 4 | 21 |
| `rustre-agent-llm` | 18157 | 554 | 3 | 85 |
| `rustre-agent-prompts` | 17345 | 527 | 1 | 42 |
| `rustre-agent-workflow` | 17760 | 508 | 1 | 14 |
| `rustre-analysis` | 19089 | 524 | 11 | 4 |
| `rustre-analysis-callconv` | 21181 | 675 | 2 | 15 |
| `rustre-analysis-cfg` | 29554 | 704 | 4 | 16 |
| `rustre-analysis-dataflow` | 26467 | 825 | 4 | 17 |
| `rustre-analysis-fn` | 22423 | 571 | 5 | 29 |
| `rustre-analysis-string` | 19454 | 679 | 2 | 53 |
| `rustre-analysis-type` | 23044 | 620 | 3 | 32 |
| `rustre-analysis-typerecov` | 9082 | 328 | 4 | 2 |
| `rustre-analysis-vsa` | 21853 | 666 | 3 | 14 |
| `rustre-analysis-vtable` | 19525 | 629 | 2 | 52 |
| `rustre-analysis-xref` | 22231 | 670 | 4 | 24 |
| `rustre-arch` | 17076 | 535 | 3 | 125 |
| `rustre-arch-6502` | 17639 | 505 | 2 | 1 |
| `rustre-arch-68k` | 21319 | 597 | 2 | 35 |
| `rustre-arch-arm` | 16845 | 713 | 2 | 2 |
| `rustre-arch-arm64` | 18654 | 771 | 2 | 7 |
| `rustre-arch-avr` | 17563 | 597 | 2 | 8 |
| `rustre-arch-bpf` | 17366 | 448 | 2 | 23 |
| `rustre-arch-cil` | 18990 | 689 | 2 | 10 |
| `rustre-arch-dex` | 16919 | 639 | 2 | 12 |
| `rustre-arch-jvm` | 18140 | 619 | 2 | 25 |
| `rustre-arch-lua` | 19016 | 722 | 2 | 24 |
| `rustre-arch-luajit` | 16863 | 751 | 3 | 31 |
| `rustre-arch-mips` | 18124 | 560 | 2 | 5 |
| `rustre-arch-msp430` | 18742 | 698 | 2 | 4 |
| `rustre-arch-ppc` | 17799 | 625 | 2 | 3 |
| `rustre-arch-registry` | 0 | 0 | 0 | 0 |
| `rustre-arch-riscv` | 20466 | 720 | 2 | 2 |
| `rustre-arch-sparc` | 18292 | 700 | 2 | 21 |
| `rustre-arch-wasm` | 16846 | 539 | 2 | 7 |
| `rustre-arch-x86` | 43992 | 1045 | 5 | 52 |
| `rustre-arch-z80` | 18385 | 669 | 2 | 8 |
| `rustre-bin` | 16724 | 412 | 0 | 103 |
| `rustre-cli` | 18162 | 568 | 0 | 54 |
| `rustre-core` | 29281 | 822 | 84 | 73 |
| `rustre-crypto-id` | 18167 | 543 | 4 | 4 |
| `rustre-crypto-oracle` | 17739 | 572 | 0 | 24 |
| `rustre-crypto-whitebox` | 15986 | 419 | 0 | 13 |
| `rustre-daemon` | 17060 | 549 | 0 | 31 |
| `rustre-db` | 5411 | 229 | 2 | 20 |
| `rustre-debug` | 133279 | 2046 | 2 | 929 |
| `rustre-decompiler` | 81136 | 1531 | 3 | 154 |
| `rustre-decompiler-c` | 17540 | 560 | 3 | 22 |
| `rustre-decompiler-cfs` | 19536 | 507 | 4 | 24 |
| `rustre-decompiler-expr` | 18038 | 657 | 4 | 43 |
| `rustre-decompiler-type` | 18362 | 614 | 4 | 6 |
| `rustre-demangle` | 53352 | 1354 | 7 | 115 |
| `rustre-deobf` | 19046 | 526 | 11 | 42 |
| `rustre-deobf-antianti` | 15651 | 343 | 1 | 14 |
| `rustre-deobf-cff` | 17684 | 484 | 1 | 22 |
| `rustre-deobf-iadl` | 16750 | 470 | 1 | 91 |
| `rustre-deobf-mba` | 16685 | 362 | 2 | 258 |
| `rustre-deobf-mhcde` | 17748 | 529 | 1 | 14 |
| `rustre-deobf-opaque` | 17310 | 467 | 1 | 70 |
| `rustre-deobf-smc` | 18437 | 492 | 1 | 70 |
| `rustre-deobf-string` | 18311 | 468 | 1 | 14 |
| `rustre-deobf-vm` | 18982 | 469 | 2 | 64 |
| `rustre-deobf-vmlift` | 18487 | 467 | 1 | 37 |
| `rustre-diff` | 19075 | 577 | 3 | 13 |
| `rustre-diff-bindiff` | 17181 | 496 | 1 | 2 |
| `rustre-diff-semantic` | 17726 | 615 | 1 | 9 |
| `rustre-dotnet` | 18137 | 522 | 3 | 18 |
| `rustre-dotnet-decompile` | 17253 | 552 | 1 | 74 |
| `rustre-dotnet-edit` | 18372 | 442 | 1 | 14 |
| `rustre-dotnet-metadata` | 18307 | 528 | 4 | 10 |
| `rustre-emu` | 19758 | 536 | 2 | 183 |
| `rustre-emu-shellcode` | 16759 | 504 | 0 | 255 |
| `rustre-events` | 17451 | 465 | 2 | 2 |
| `rustre-flirt` | 18249 | 520 | 4 | 13 |
| `rustre-flirt-apply` | 30198 | 798 | 7 | 43 |
| `rustre-flirt-gen` | 19893 | 559 | 3 | 15 |
| `rustre-forensics` | 17406 | 380 | 5 | 32 |
| `rustre-forensics-fs` | 19233 | 610 | 1 | 67 |
| `rustre-forensics-mem` | 17692 | 644 | 3 | 71 |
| `rustre-forensics-plugins` | 17664 | 342 | 1 | 35 |
| `rustre-fuzz` | 17261 | 598 | 4 | 3 |
| `rustre-fuzz-afl` | 17746 | 676 | 3 | 29 |
| `rustre-fuzz-cov` | 18419 | 569 | 3 | 9 |
| `rustre-fuzz-libfuzzer` | 17443 | 524 | 1 | 14 |
| `rustre-fuzz-net` | 17205 | 521 | 1 | 18 |
| `rustre-fuzz-sanitizers` | 20752 | 661 | 3 | 1 |
| `rustre-graph` | 18410 | 391 | 1 | 8 |
| `rustre-gui` | 127122 | 396 | 0 | 170 |
| `rustre-hex` | 19636 | 746 | 4 | 9 |
| `rustre-hex-pattern` | 17493 | 569 | 1 | 15 |
| `rustre-hex-template` | 17840 | 478 | 1 | 6 |
| `rustre-hex-view` | 17936 | 639 | 1 | 15 |
| `rustre-il` | 0 | 0 | 6 | 0 |
| `rustre-il-hlil` | 27345 | 610 | 2 | 19 |
| `rustre-il-lift` | 91429 | 2546 | 4 | 56 |
| `rustre-il-llil` | 23627 | 588 | 9 | 36 |
| `rustre-il-mlil` | 22094 | 503 | 4 | 20 |
| `rustre-il-passes` | 24304 | 553 | 2 | 32 |
| `rustre-knowledge` | 5854 | 244 | 1 | 1 |
| `rustre-loader` | 20117 | 642 | 3 | 99 |
| `rustre-loader-android` | 17514 | 555 | 2 | 78 |
| `rustre-loader-console` | 19222 | 534 | 2 | 28 |
| `rustre-loader-dotnet` | 19395 | 625 | 2 | 73 |
| `rustre-loader-elf` | 22393 | 640 | 3 | 143 |
| `rustre-loader-firmware` | 17104 | 646 | 2 | 20 |
| `rustre-loader-java` | 17457 | 507 | 2 | 49 |
| `rustre-loader-lua` | 17931 | 581 | 2 | 103 |
| `rustre-loader-luajit` | 17280 | 523 | 2 | 74 |
| `rustre-loader-macho` | 16613 | 533 | 3 | 83 |
| `rustre-loader-ole` | 19058 | 640 | 2 | 37 |
| `rustre-loader-pdf` | 16216 | 453 | 2 | 13 |
| `rustre-loader-pe` | 19870 | 625 | 8 | 63 |
| `rustre-loader-registry` | 0 | 0 | 0 | 0 |
| `rustre-loader-wasm` | 17047 | 464 | 2 | 38 |
| `rustre-mcp` | 18301 | 562 | 0 | 63 |
| `rustre-mcp-federation` | 18645 | 552 | 1 | 98 |
| `rustre-mcp-server` | 19078 | 486 | 4 | 203 |
| `rustre-mcp-tools` | 129535 | 330 | 2 | 703 |
| `rustre-mem` | 25024 | 901 | 3 | 8 |
| `rustre-mobile` | 0 | 0 | 1 | 0 |
| `rustre-mobile-android` | 15184 | 458 | 1 | 93 |
| `rustre-mobile-apktool` | 16247 | 509 | 2 | 91 |
| `rustre-mobile-dyld` | 19106 | 492 | 2 | 174 |
| `rustre-mobile-ios` | 18714 | 578 | 2 | 172 |
| `rustre-mobile-ipa` | 16790 | 455 | 2 | 79 |
| `rustre-mobile-jadx` | 18689 | 567 | 2 | 181 |
| `rustre-mobile-smali` | 17003 | 407 | 2 | 100 |
| `rustre-net` | 17630 | 474 | 7 | 8 |
| `rustre-net-dissect` | 23035 | 559 | 3 | 5 |
| `rustre-net-pcap` | 16909 | 428 | 2 | 16 |
| `rustre-net-proxy` | 18735 | 598 | 1 | 17 |
| `rustre-net-rules` | 19063 | 518 | 1 | 16 |
| `rustre-patch` | 6568 | 264 | 3 | 1 |
| `rustre-pe-editor` | 18537 | 534 | 1 | 24 |
| `rustre-pe-rebuild` | 18071 | 516 | 1 | 57 |
| `rustre-pe-tools` | 16505 | 460 | 7 | 73 |
| `rustre-plugin-api` | 19353 | 684 | 2 | 127 |
| `rustre-plugin-host` | 16653 | 585 | 0 | 66 |
| `rustre-plugin-loader` | 4283 | 242 | 0 | 0 |
| `rustre-plugin-lua` | 2309 | 153 | 1 | 0 |
| `rustre-plugin-native` | 1833 | 111 | 1 | 1 |
| `rustre-plugin-python` | 3067 | 178 | 1 | 58 |
| `rustre-project` | 18531 | 672 | 1 | 28 |
| `rustre-sandbox` | 16493 | 429 | 5 | 104 |
| `rustre-sandbox-extract` | 16907 | 446 | 0 | 51 |
| `rustre-sandbox-monitor` | 15670 | 374 | 0 | 29 |
| `rustre-sandbox-report` | 17289 | 553 | 1 | 199 |
| `rustre-sandbox-vm` | 16142 | 270 | 1 | 52 |
| `rustre-script` | 17599 | 576 | 1 | 62 |
| `rustre-script-lua` | 19289 | 629 | 2 | 66 |
| `rustre-script-python` | 18740 | 606 | 2 | 337 |
| `rustre-script-rhai` | 17623 | 732 | 2 | 89 |
| `rustre-symb` | 19927 | 637 | 3 | 41 |
| `rustre-symb-engine` | 16693 | 540 | 1 | 7 |
| `rustre-symb-taint` | 17111 | 402 | 0 | 21 |
| `rustre-symbols` | 24590 | 842 | 7 | 63 |
| `rustre-symbols-codeview` | 18369 | 452 | 0 | 4 |
| `rustre-symbols-dwarf` | 19955 | 484 | 3 | 14 |
| `rustre-symbols-pdb` | 20215 | 484 | 5 | 8 |
| `rustre-symbols-stabs` | 19960 | 575 | 1 | 6 |
| `rustre-syscalls` | 17344 | 469 | 3 | 135 |
| `rustre-syscalls-linux` | 16677 | 606 | 1 | 1 |
| `rustre-syscalls-windows` | 19545 | 530 | 1 | 166 |
| `rustre-sysinternals` | 17305 | 450 | 2 | 38 |
| `rustre-threatintel` | 20066 | 586 | 8 | 38 |
| `rustre-ti-correlate` | 16016 | 495 | 0 | 23 |
| `rustre-ti-malpedia` | 16829 | 556 | 1 | 101 |
| `rustre-ti-misp` | 18851 | 541 | 1 | 56 |
| `rustre-ti-opencti` | 3159 | 46 | 1 | 0 |
| `rustre-ti-otx` | 3513 | 167 | 1 | 0 |
| `rustre-ti-shodan` | 2398 | 123 | 0 | 0 |
| `rustre-ti-vt` | 16163 | 479 | 1 | 80 |
| `rustre-trace` | 18875 | 529 | 3 | 7 |
| `rustre-trace-coresight` | 17964 | 569 | 2 | 4 |
| `rustre-trace-coverage` | 17411 | 491 | 2 | 14 |
| `rustre-trace-navigate` | 19354 | 506 | 3 | 0 |
| `rustre-trace-pt` | 19802 | 687 | 2 | 6 |
| `rustre-triage` | 15997 | 344 | 7 | 20 |
| `rustre-triage-die` | 19610 | 510 | 2 | 23 |
| `rustre-triage-entropy` | 18926 | 687 | 3 | 7 |
| `rustre-triage-peid` | 16149 | 387 | 1 | 42 |
| `rustre-triage-yara` | 16869 | 362 | 0 | 5 |
| `rustre-ttd` | 17484 | 629 | 5 | 4 |
| `rustre-ttd-query` | 18126 | 503 | 1 | 1 |
| `rustre-ttd-recorder` | 18698 | 524 | 1 | 13 |
| `rustre-ttd-replay` | 19199 | 554 | 1 | 1 |
| `rustre-ttd-replayer` | 17923 | 561 | 1 | 4 |
| `rustre-yara` | 17526 | 450 | 4 | 10 |
| `rustre-yara-engine` | 18144 | 512 | 3 | 26 |
| `rustre-yara-rules` | 15959 | 215 | 1 | 24 |

---

## Appendice B — Metodologia di misura

Ogni numero di questo documento è riproducibile con i comandi seguenti, eseguiti dalla root del repository.

**Conteggio crate e righe**

```bash
ls crates | wc -l
find crates -name '*.rs' | wc -l
find crates -name '*.rs' -exec cat {} + | wc -l
find crates -name '*.rs' -printf '%s\n' | awk '{s+=$1} END{print s}'
```

**Quota di righe-test** — una riga è contata come test da `mod tests` fino a fine file:

```bash
find crates -name '*.rs' -exec awk 'FNR==1{it=0} /^[[:space:]]*(pub )?mod tests/{it=1} \
  {T++; if(it)S++} END{printf "%d %d\n",T,S}' {} +
```

**Grafo delle dipendenze inverse** — per ogni crate, quanti altri `Cargo.toml` la nominano:

```bash
for c in $(ls crates); do
  n=$(grep -rl "\"$c\"\|^\s*$c\s*=" crates/*/Cargo.toml \
      | grep -v "crates/$c/Cargo.toml" | wc -l)
  echo "$n $c"
done | sort -n
```

**Densità di marcatori stub**

```bash
find crates/<nome>/ -name '*.rs' -exec \
  grep -aciE 'stub|mock|placeholder|not implemented|simplified|todo' {} +
```

**Attributi allow**

```bash
grep -rho '#!\?\[allow([^]]*)\]' crates --include='*.rs' | sort | uniq -c | sort -rn
```

**Compilazione**

```bash
cargo check --workspace --release --all-targets --message-format short
```

**Note sull'affidabilità delle misure**

- `grep -a` è necessario: `crates/rustre-debug/src/codeview/codeview_parser.rs` contiene byte che `grep` classifica come binari e salterebbe silenziosamente.
- Il conteggio delle righe con `xargs ... | wc -l` **sottostima**: con 4.092 file `xargs` divide in più invocazioni e produce più righe `total`. Va usato `-exec ... +` con un solo `wc` finale, oppure sommate tutte le parziali.
- I conteggi di marcatori sono **occorrenze per riga**, non identificatori distinti: una riga con `stub` e `mock` conta due volte. Sono indicatori di densità, non inventari — l'inventario vero è il lavoro del punto 6 del piano.
- I `revdeps` contano le menzioni nei manifest, incluse le dipendenze `optional`. Una crate `optional` disattivata risulta comunque come dipendenza.

---
---

# Addendum — sessione 2026-08-18

> **Regola di questo documento: si aggiunge, non si toglie.** Nulla sopra questa
> riga è stato cancellato o riscritto, comprese due conclusioni che questa
> sessione ha dimostrato **sbagliate** (§A.2). Restano visibili accanto alla
> versione corretta, perché un documento che cancella i propri errori non
> permette di controllare il metodo che li ha prodotti.

## A.0 Sintesi dell'addendum

| Voce | Prima | Dopo |
|---|---|---|
| Warning fuori da `rustre-debug` e dal lint di policy `unsafe` | 498 in tutto il workspace | **0** |
| Errori di compilazione | 0 | **0** |
| Attributi `#[allow(...)]` | 382 | **159** (234 rimossi; alcuni rientrati dal lavoro concorrente su `rustre-debug`) |
| Tool MCP resi raggiungibili | — | **+50** |
| Tool MCP che riferivano su una fixture interna senza accettare input | 21 | **8** |
| Difetti reali trovati e chiusi | — | **17** (§A.3) |

Commit della sessione: `7c33d8b`, `8940d98`, `ca13eb1`, `e45c91a`.

---

## A.1 Cosa è stato fatto, in ordine

### 1. Il diff da 953 righe — committato (`7c33d8b`)

Il port di `data_symbol_definitions` da path B a path A, che §7.2a descriveva
come «la cosa di maggior valore attualmente non protetta da un commit». Con esso
`EmptyBlockEliminator::eliminate_preserving_entry` e `RULES.md`.

### 2. STATUS.md — committato (`8940d98`)

Il documento sopra, 811 righe, con l'appendice completa delle 190 crate.

### 3. `CLAUDE.md` riallineato alla baseline misurata

Quattro numeri erano falsi. Ora il file porta una sezione `BASELINE 2026-08-18
— runs/base_0818` che precede ogni cifra più vecchia:

| metrica | valore misurato |
|---|---|
| file emessi | 11342 |
| arity vs 135 prototipi | 122/135 (90,4%) — 6 OVER, 7 UNDER |
| fidelity, 16 pubblicati | **14/16** (regressione reale, causa isolata) |
| behaviour | **15/63** (23,8%) — è cambiata la scala, non il codice |
| `goto` emessi | **0** su 11342 |
| `JUMPOUT` | 18, in 12 file, tutti C# |
| data symbol definiti (path A) | 5427 |
| unresolved actionable | 4012 |

Più quattro cose che il file non diceva: la causa isolata della regressione di
fedeltà (regola D9 in `win64_param_regs_live_in`, `lib.rs:2450`, che propaga
l'errore **verso l'alto**); che `JUMPOUT` non è estetica ma rompe il link; che
~28% dei file chiama funzioni mai dichiarate; e che esiste una sesta metrica,
`callsite_consistency.py`, con 9756 OVER / 6042 UNDER su 10330 definizioni.

### 4. I 234 `allow` rimossi, e cosa nascondevano (`ca13eb1`)

Rimossi per primi, poi i warning emersi chiusi **aggiungendo** codice.

- **50 tool MCP scritti, compilati e irraggiungibili.** 28 tool SPARC completi
  su `rustre_arch_sparc::*` che nessuno costruiva, più
  `push_decompiler_type_extra_handlers` e `dataflow_extra_handlers` — le due
  funzioni che registrano **gruppi interi** (10 + 12 tool), entrambe già in
  scope via `include!` e mai chiamate.
- **Il registro delle architetture conteneva solo stub** (§A.2).
- **36 test nuovi**, ciascuno scritto per *usare* una fixture senza chiamanti —
  motivo per cui le lacune erano invisibili: layout ABI MSVC mai testato,
  programma DWARF mai eseguito end-to-end, staleness della cache mai verificata,
  flag `TypeDef` .NET, contenimento delle patch PE, scrittura dello stack
  pointer su CALL/RET a 32 bit, robustezza del trie dyld su ogni troncamento,
  larghezze intere in propagazione e unificazione.

### 5. I dati finti — sette agenti in parallelo (`e45c91a`)

Vedi §A.4 per la classificazione e §A.5 per ciò che gli agenti hanno trovato.

---

## A.2 Due conclusioni di questo documento che erano SBAGLIATE

Restano scritte sopra. Ecco la correzione.

### Errore 1 — §3.2: «i registry sono gusci»

**Sbagliato.** `rustre-arch-registry` (77 righe) cabla davvero tutte e 19 le
architetture; `rustre-loader-registry` (215) ha adattatori completi per 13
formati; `rustre-mobile` (43) ri-esporta tutti e 7 i sotto-crate; `rustre-il`
(152) è una crate di primitive condivise con 6 dipendenti — perfettamente sana.
Sono piccole perché sono crate di **composizione**: è la dimensione giusta per
quel lavoro. Ho dedotto un difetto dalla dimensione invece di leggere il
contenuto.

**Il difetto vero è peggiore, ed è stato misurato:**

> `rustre_arch_registry::register_all()` — che installa i 19 backend reali —
> **non era chiamata da nessuno nel workspace.** L'unico chiamante in
> quest'area è `rustre-bin/src/format_detector.rs:278`, che chiama
> `rustre_arch::register_all_builtins()`: quella installa `PlaceholderArch`, il
> cui `disassemble` restituisce `Err("PlaceholderArch: no backend linked")`.

Il registro globale del binario era fatto **interamente di stub che si rifiutano
di disassemblare**, mentre ogni backend reale stava compilato e non installato.
E la funzione si documentava come «*ensuring every bundled `rustre-arch-*` crate
is reachable at runtime*».

**Chiuso**: `rustre-bin` dipende ora da `rustre-arch-registry` e chiama
`register_all()` dopo `register_all_builtins()`, in quest'ordine, così
un'architettura senza backend resta elencata come stub invece di sparire.

Lezione, dello stesso tipo di quelle già in §6: **P1 non era non implementato.
Era implementato e mai invocato.** La differenza è invisibile a un conteggio di
righe e a un grafo di dipendenze, e visibile solo leggendo chi chiama cosa.

### Errore 2 — §6: «~8.000 punti di mock»

**Sovrastima grossolana.** In reverse engineering **"stub" è vocabolario di
dominio**: un IAT stub, un PLT stub, un thunk, uno stub pure-virtual. Misurato:

| Classe | Quantità | Verdetto |
|---|---|---|
| `pub fn` con `stub` nel nome che sono **analisi reali sugli stub** (`identify_stub_pattern`, `find_stubs`, `is_stub`, `populate_libc_stubs`, `plt_entries`) | **58** | **non è un difetto** |
| Funzioni che **costruiscono dati inventati** (`mock_*`, `fake_*`, `dummy_*`) | **32** | difetto |
| **Tool MCP** con `mock` nel nome, esposti all'utente | **54** | difetto, il peggiore |
| Marcatori d'intento (`in a real implementation`, `for now`) in `src/` | ~500 | ammissioni di incompletezza |

Il conteggio di 8.000 sommava anche commenti che spiegano perché una cosa **non**
è un mock. La cifra da citare è ~90 funzioni più 54 tool, non 8.000.

Ciò che §6 dice sul **rapporto** resta vero e resta la diagnosi: **1 solo
`todo!()`** in tutto il workspace, oggi come allora. Il codice, dove è
incompleto, continua a restituire un valore plausibile invece di fallire. È la
superficie del problema a essere più piccola di quanto scritto, non la sua
natura.

---

## A.3 I 17 difetti reali trovati e chiusi

Ordinati per gravità.

1. **Il registro delle architetture installava solo placeholder** (§A.2). Ogni
   disassemblaggio via registro globale falliva con "no backend linked".
2. **`LineProgram::parse` (DWARF) accettava unità troncate.**
   `unit_end = pos + unit_length` non era mai confrontato con `data.len()`, e
   `parse` restituiva un offset "prossima unità" **fuori dal buffer**. Input
   controllato dall'attaccante in uno strumento RE. 323/323 verdi dopo il fix.
3. **Il walker DIE scartava silenziosamente attributi validi.**
   `DW_AT_decl_line`/`decl_file` matchavano solo `AttrValue::Uint`; codificati
   come `DW_FORM_sdata` (legale, e prodotto da alcuni compilatori) venivano
   decodificati correttamente e poi buttati via da `_ => {}`. La funzione
   risultava senza riga né file, senza alcun errore.
4. **Il walker DIE emetteva le dichiarazioni come definizioni.** Una DIE con
   `DW_AT_declaration` descrive una funzione definita altrove: emetterla
   attribuiva un intervallo di indirizzi a un corpo assente.
5. **`HexNormalizerPass` corrompeva le regole YARA.** `in_hex` si attivava alla
   prima `{`, che è quella del corpo: il pass maiuscolava gli **identificatori**,
   `$a` diventava `$A`, e `condition: $a` non si riferiva più alla stringa
   definita.
6. **`has_catastrophic_backtracking` non trovava il proprio esempio canonico.**
   Ciclo su `0..len-4`; in `(a+)+b` il `+` interno è all'indice 2 e `len-4` è 2.
   Off-by-two: il rilevatore era cieco al caso che il suo test asseriva.
7. **Tre moduli interi di regole YARA reali mai caricati.**
   `apt_detection_rules`, `packer_detection_rules`, `ransomware_rules` erano
   `pub mod` in `lib.rs` e alimentavano nulla. 99 → 138 regole.
8. **WannaCry e Mimikatz non esistevano nel database di regole.** Aggiunte con
   indicatori pubblicati, più LockBit, Conti, Cobalt Strike. Totale 143.
9. **`test_seq_by_category` codificava una convinzione sbagliata**: si aspettava
   che `CreateRemoteThread` non fosse process injection. Lo è, e il
   classificatore lo diceva. Corretto il test, non il codice.
10. **Un test vacuo**: `assert!(stats.converted_to_continue >= 0)` su un unsigned
    non può fallire — e guardava pure il contatore sbagliato: misurato, quel
    `goto` viene rimosso invertendo la guardia, non con un `continue`.
11. **`detect_base64_variant` decideva per esclusione**, con l'evidenza positiva
    (`has_plus_slash`) calcolata e mai letta.
12. **`expr_complexity` teneva un catch-all** che il commento sopra accusa di
    aver pesato `Sar` come 1 qualunque fosse il suo sottoalbero, facendolo
    vincere sempre come "più semplice". Match ora esaustivo.
13. **Un test differenziale non testava il caso che sembrava coprire**: l'array
    era costruito fuori dal ciclo e sovrascritto prima della prima lettura, così
    il caso tutto-NUL non veniva mai esercitato.
14. **`req_str` definita identica in due file**, usata 83 volte in uno e mai
    nell'altro — due definizioni dello stesso contratto, libere di divergere.
15. **Il fallback di `make_backend` era codice morto su ogni piattaforma
    supportata**; ora cfg-gated, così aggiungere un backend senza estendere
    l'elenco è un errore di compilazione.
16. **Sei attributi `#[test]`/`#[must_use]` duplicati.**
17. **Tre frasi false nel sorgente**, il pattern che questo repo conosce già:
    «*its callers still want that*» su una funzione senza chiamanti; «*Used to
    curb over-detection*» su un predicato mai invocato; e la più costosa,
    «*ensuring every bundled `rustre-arch-*` crate is reachable at runtime*».

---

## A.4 Il confine dove la fabbricazione raggiungeva l'utente

Tre agenti indipendenti hanno trovato **lo stesso difetto sistemico**, che non
stava nei crate ma nel wrapper MCP:

> **21 tool MCP dichiaravano `input_schema: {"properties": {}}`** — non
> accettavano alcun argomento — costruivano una fixture, la analizzavano e ne
> riportavano il risultato.

Rendere reali gli analizzatori sottostanti non cambiava nulla: i byte analizzati
restavano fabbricati. Un client che chiedeva «quali processi giravano in questo
dump» riceveva i processi che il workspace aveva appena scritto in un proprio
buffer da 4 KiB, e non aveva **nessun modo** di passare un dump.

Chiusi in questa sessione (21 → 8):

| Gruppo | Tool | Ora prende |
|---|---|---|
| forensics memoria | 8 | `path`, con rilevamento del container per magic (MDMP / ELF core / flat) |
| IPA iOS | 8 | `path` del `.ipa` |
| Malpedia | 4 | `corpus_path` (nuovo `MalpediaLocalDb::load_json`/`load_path`) |
| sandbox report | 5 | il `SandboxReport`/`IocSet` reale da renderizzare |

Restano 8 wrapper mobile/jadx dello stesso tipo.

**Principio applicato**: dove una fixture resta raggiungibile, è dietro un
opt-in esplicito che **etichetta** l'output (`is_synthetic_fixture`,
`is_reference_fixture`, o il banner `SYNTHETIC FIXTURE` che il renderer già
emette e che ha un test). Una fixture chiesta per nome non è la stessa cosa di
una fixture consegnata in silenzio.

**Nota su `MalpediaLocalDb`**: prima di questa sessione gli unici modi di
riempirlo erano `insert_*` un record alla volta e `populate_mock_data`. I tool
MCP usavano il secondo. Non esisteva alcun modo di puntare il client a dati
reali **nemmeno avendoli**.

---

## A.5 Cosa hanno trovato gli agenti nei crate

Sette agenti su 22 crate. Selezione di ciò che il mock nascondeva.

- **Il parser Lua 5.1/5.2 non poteva parsare bytecode `luac` autentico.** Due
  difetti: il campo `nups` non veniva letto (spostando di un byte tutto ciò che
  segue — conteggio istruzioni, array del codice, pool delle costanti), e le
  lunghezze delle stringhe erano lette come `int` invece che `size_t`, quindi su
  qualunque build a 64 bit il primo campo (il nome del sorgente) era già
  sbagliato. **Invisibile perché le uniche fixture di test 5.1 erano costruite
  con lo stesso layout errato.**
- **Il recupero async .NET falliva su assembly reali.** Compilato un assembly
  vero con `dotnet`, il bridge recupera la state machine autentica
  (`<DoWorkAsync>d__0`, campi reali, `MoveNext` di 110 istruzioni), ma
  `decompile_async` non trova lo switch di stato: Roslyn emette
  `brfalse`/`bne.un` per state machine piccole, non una `switch` table — e il
  mock ne emetteva **sempre** una, quindi ogni test passava contro una forma che
  il compilatore non produce.
- **`IpaPackage::parse` fabbricava un bundle quando `Info.plist` mancava**
  (`bundle_version: "1.0"`, `min_os_version: "14.0"`), valori che serializzano
  identici a quelli parsati. `CFBundleSupportedPlatforms` era hardcoded a
  `iPhoneOS` su ogni percorso, quindi `targets_iphone` era vero anche per un
  bundle watchOS. `is_adhoc` era `cert_chain.is_empty()`, cioè riportava un
  limite del parser come proprietà della firma.
- **`LinuxAnalyzer::find_sockets` era il percorso Windows**, chiamato alla
  lettera: i "socket Linux" erano record Windows.
- **`ApktoolRunnerImpl` era un secondo fabbricatore non elencato**:
  `decode("app.apk")` restituiva percorsi inventati per un file mai esistito, e
  `build` restituiva `size_bytes: 0` come "successo".
- **Due client per servizio, uno vero e uno finto**, con API quasi identiche e
  nessun segnale su quale fosse quale (`VtClient` vs `VirusTotalClient`,
  `MispClient` vs `MispApiClient`).
- **`OtxPulse::sample()` era esposto come tool MCP** — una fixture di test
  consegnata come intelligence, con un IP instradabile e un'attribuzione a
  Emotet.

---

## A.6 Cosa resta aperto

1. **8 tool MCP mobile/jadx** ancora senza input, stesso schema di §A.4.
2. **`RegistryHive::parse_key`** (raggiungibile via MCP) fabbrica ancora: per
   qualunque path in qualunque buffer che inizi con `regf` restituisce una
   chiave chiamata come l'ultimo segmento del path, con `LastWriteTime` a zero e
   nessuna sottochiave — non cammina mai le celle `nk`/`lf`/`vk`.
3. **`MAX_REGION_READ` tronca in silenzio**: ogni scanner forensics legge al
   massimo 64 MiB per regione. Su un dump reale da più GB esposto come una sola
   regione, solo i primi 64 MiB vengono esaminati, e **nulla segnala che lo scan
   è parziale**.
4. **`rustre-decompiler-c`: 6 test falliti pre-esistenti.**
   `as_c_declaration()` emette `int`, i test pretendono `int32_t`. Entrambi sono
   codice committato e non modificato — l'unica modifica in
   `rustre-decompiler-type` è un import di test di una riga, che non può
   raggiungere `c_name`. Decidere quale grafia è giusta cambia i nomi di tipo
   emessi su tutto il corpus: va misurato con `measure.sh`, non deciso a mano.
5. **`rustre-debug`: 133 warning**, non toccati perché un'altra sessione lavora
   su quel crate in parallelo.
6. **Il lint di policy `unsafe_code`: 114 occorrenze.** Non è un difetto: la
   crate imposta deliberatamente `#![warn(unsafe_code)]` perché ogni blocco
   `unsafe` resti visibile. Silenziarlo richiede un `allow` (vietato) o
   cancellare l'`unsafe` (fuori scopo). Va lasciato acceso.
7. **Il punto 5 del piano — Z3/Unicorn — non è stato affrontato.** La scelta fra
   reintrodurli come feature opzionale o riscrivere `info.txt` §11/§12/§13 resta
   aperta, ed è ancora la sorgente strutturale della classe di mismatch.
8. **Il punto 6 — mock → `todo!()`** — è stato eseguito nella forma additiva che
   §10 prescriveva: inventario, classificazione, e sostituzione con **errori
   tipizzati** anziché con `todo!()`. Un errore tipizzato che nomina ciò che
   manca è più utile di un panic e non rompe i chiamanti. `todo!()` resta a 1.

---

## A.7 Nota di metodo

Tre volte in questa sessione la misura ha smentito la deduzione, e ogni volta la
deduzione era mia:

1. Ho concluso che i registry fossero vuoti **dalla loro dimensione**. Erano
   completi e non chiamati (§A.2).
2. Ho contato ~8.000 mock **da un grep**. Erano ~90 più 54 tool; il resto era
   vocabolario di dominio e commenti che dicevano il contrario (§A.2).
3. Ho scritto un test che asseriva 2 campi di layout. Il motore ne restituisce 3,
   perché materializza il padding come campo esplicito — comportamento migliore
   di quello che avevo assunto.

E un errore di coordinamento reale: il commit `ca13eb1` ha inglobato parte del
working tree di altri agenti, perché ho eseguito `git add -A` mentre lavoravano.
Il lavoro è salvo, ma attribuito al commit sbagliato.

Il corollario operativo è quello già scritto in §4.3, e vale anche per chi scrive
questo documento: **nessuna affermazione qui dentro vale più della misura che la
sostiene**, e le tre correzioni sopra sono lasciate visibili apposta.

---

# Addendum B — gli `allow`, e la misura che ha cambiato l'obiettivo

> Additivo come il resto del documento. Nulla sopra è stato tolto.

## B.0 Il numero che mancava

Prima di tutto, la correzione più importante di questo addendum:

> **`cargo check` non esegue i lint clippy.**

Tutte le cifre "0 warning" di §A.0 sono **rustc**. Gli `#[allow(...)]` sopprimevano
lint **clippy**, e la superficie clippy del workspace è:

| | |
|---|---|
| Warning **rustc** fuori da `rustre-debug` | **0** |
| Warning **clippy** in tutto il workspace | **13.370** |

Non è mai stata vicina a zero. Rimuovere un `allow` in un file che ha centinaia
di altri warning clippy cambia quasi nulla, e dire il contrario sarebbe
esattamente il tipo di affermazione falsa che questo repo continua a trovare nei
propri commenti.

## B.1 Il risultato

| | Prima | Dopo |
|---|---|---|
| `allow` attivi | 132 | **30** |
| ↳ in `rustre-debug` (altra sessione) | — | 8 |
| ↳ con `reason = "..."` leggibile dalla macchina | 2 | **9** |
| Warning rustc fuori da `rustre-debug` e dal lint `unsafe` | 0 | **0** |
| `rustre-arch` — warning clippy, tutti i target | 11 | **0** |
| `rustre-dotnet-metadata` — warning clippy | 511 | **73** |

## B.2 Perché i blocchi generici sono tornati, ristretti

Nove blocchi `#![allow(...)]` da 45-59 righe (in `fuzz` ×5, `dotnet-metadata`,
`loader-android`, `mobile-android`, `arch`) coprivano ~15 categorie di lint
ciascuno. Rimuoverli ha scoperto **~1043 warning** in quei cinque crate.
`cargo clippy --fix` si rifiuta di applicare i propri suggerimenti lì
(«errors present after applying fixes»), quindi non era lavoro meccanico.

I blocchi sono tornati **ristretti**, e la restrizione è il punto:

- **Fuori dalla lista, quindi visibili**: `cast_possible_truncation`,
  `cast_sign_loss`, `cast_possible_wrap`, `cast_lossless`. In uno strumento di
  reverse engineering un `as` che tronca un indirizzo produce una risposta
  sbagliata che sembra giusta.
- **Dentro la lista**: presentazione (attributi che clippy vorrebbe aggiunti,
  formattazione dei doc, raggruppamento dei letterali) più
  `cast_precision_loss`, la cui unica conseguenza qui è una statistica
  arrotondata.

`dotnet-metadata` è passato da 511 a 73 warning così, con i ~60 cast **ancora
visibili** invece che sepolti sotto 450 di stile. **Un warning che nessuno legge
è peggio di nessun warning** — è lo stesso argomento che §4.3 fa sui test verdi.

## B.3 Difetti reali trovati

1. **`SharedCorpus::add_entry` restituisce se l'input è stato ACCETTATO** — lo
   rifiuta se non aggiunge copertura — e `sync_to_shared` buttava via quel bool.
   Per un fuzzer è il numero che conta: un worker che sincronizza 500 input di
   cui 0 nuovi era indistinguibile da uno che ne sincronizza 500 nuovi. Ora
   `sync_to_shared` restituisce il conteggio accettato. Emerso perché un
   `#[must_use]` ha trasformato lo scarto in errore, sotto
   `unused_must_use = "deny"` del workspace.
2. **Due `allow` erano stantii**: `approx_constant` in `dotnet-decompile` e
   `float_cmp` in `arch` non sopprimevano più niente. Verificato, rimossi.
3. **Sette `assert_eq!(density, 0.0)`** sostituiti da confronti su `to_bits()`:
   è un confronto **intero** (niente lint) ed è anche **più severo**, perché
   rifiuta `-0.0`, che per una densità indicherebbe un bug di segno.

## B.4 Le struct di parametri, e perché il lint aveva ragione

`too_many_arguments` non segnalava la lunghezza, segnalava un pericolo:

| Funzione | Il pericolo |
|---|---|
| `strongconnect` (Tarjan) → `TarjanState` | sei `&mut` vettori di fila: trasporne due **compila** e calcola SCC sbagliate |
| `parse_version_info_endian` → `VersionSections` | quattro `&[u8]` di fila: scambiare `verneed_data` e `verdef_data` **compila** e dà una risposta plausibile e falsa, perché entrambi si leggono contro lo stesso `.dynstr` |
| `classify54`/`classify_legacy` → `InstrCtx` + `ClassifySink` | undici parametri, quattro `usize` consecutivi e cinque `&mut` consecutivi |

Campi con un nome rendono lo scambio **impossibile da scrivere**.

## B.5 Un allow tenuto apposta, con il warning visibile

`rustre-deobf::casts` **non ha più l'allow e il warning clippy resta visibile**.
La ragione è tecnica e va scritta perché non venga "risistemata" da qualcuno:

> Non esiste una conversione float→intero verificata in `std` — `try_from` non è
> implementato per sorgenti float. `f64 as u32` **è** la conversione saturante
> corretta, e il `clamp` sopra ne prova il limite. Le uniche alternative erano
> rimettere l'attributo o lasciare il warning.

Un tentativo precedente instradava la conversione attraverso `u64` credendo di
renderla verificata: `clamped as u64` è un cast float→int identico, e clippy lo
segnalava **una riga più sotto**. Il problema era stato spostato, non risolto.
Quel tentativo è registrato nel commento del sorgente perché nessuno lo ripeta.

## B.6 I 30 `allow` rimasti, con verdetto

**Corretti, e ora lo dichiarano** (`reason = "..."`, 9):

| Dove | Perché è corretto |
|---|---|
| `SymExpr::Const` / `Symbol` / `Ite` | costruttori che specchiano il nome della variante, **3979 chiamanti** |
| `AF_shadow()` | la maiuscola **è** la funzionalità: ogni datasheet Z80 scrive `AF'`, e lo snake_case `af_shadow()` esiste già accanto |
| I due moduli IDA-compat | i nomi **sono** il contratto con gli script IDA esistenti; rinominarli toglie l'unica ragione per cui quei moduli esistono |
| Tre `unsafe_code` | rimuoverli significherebbe cancellare il codice `unsafe` |

**In `rustre-debug`** (8): non toccati, un'altra sessione ci lavora in parallelo.

**Restanti** (~13): `too_many_lines` su funzioni la cui divisione è a rischio o a
valore nullo, più i quattro blocchi solo-stile di §B.2, che portano dentro di sé
la spiegazione di cosa è stato tolto dalla lista e perché.

## B.7 Cosa resta aperto, in aggiunta a §A.6

9. **13.370 warning clippy nel workspace.** È l'obiettivo che *sembrava* essere
   quello degli `allow`, ed è di ordini di grandezza più grande. È anche dove
   stanno i difetti veri: in questa sessione i cast hanno rivelato tre bug
   distinti. Va affrontato per classi di lint, misurando a ogni passo.
10. **`crates/rustre-decompiler/src/binary_entry.rs` non compila** — 112 righe
    non committate di un'altra sessione, il cui test destruttura una coppia da
    una funzione che ora restituisce una tripla. Modifica loro, correzione loro.
