# STATUS — `rustre-debug`

> **Cruscotto del debugger.** Aggiornato a **ogni iterazione**. Ogni numero qui è
> **misurato**, mai stimato: se una cosa non è stata misurata, è scritto che non
> lo è stata.
>
> **Ogni 4 iterazioni questo file va riscritto da zero**, non solo esteso: il
> semaforo e le dimensioni si rimisurano, i difetti chiusi escono dalla tabella
> degli aperti, le iterazioni vecchie si comprimono in una riga di totale. Un
> numero non rimisurato durante il consolidamento va marcato come non misurato.
>
> Ultimo aggiornamento: **iterazione 556** · 2026-08-15
> **Riscrittura completa.** La precedente era al 549; il consolidamento del 552
> è stato **saltato** e questo lo recupera. Prossima: iterazione 560.

---

## 1. Il traguardo, e il suo limite esatto

**macOS è stato eseguito su hardware Apple, e il backend passa.** Job CI
`macOS Apple Silicon` → `success`, incluso `Test rustre-mcp-tools`. Era il limite
dichiarato del progetto da 539 iterazioni.

Ma i **primi test live macOS** (iterazione 551) hanno subito circoscritto quanto
vale:

```
launch_runs_a_child_to_exit ......................... PASSA
the_task_port_is_obtainable_for_our_own_child ....... FALLISCE
a_stopped_thread_reports_a_pc_inside_a_mapped_region  FALLISCE
a_software_breakpoint_..._apple_silicon ............. FALLISCE

task_for_pid failed (kern_return 5) — needs root or the debugger entitlement
```

`fork` + `PT_TRACE_ME` + `execvp` e il ciclo di wait funzionano **senza
privilegi**. Tutto ciò che richiede una **task port Mach** no. È un fatto di
deployment, non un dettaglio di CI: chi installa questo debugger su un Mac deve
saperlo prima di scoprirlo da un utente.

---

## 2. Semaforo

| Indicatore | Valore | Note |
|---|---|---|
| **Test Windows** (fuori da `ios::`) | **1940 / 1940** ✅ | rimisurato al 554 |
| **Test Linux** (WSL, seriale) | **1926 / 1926** ✅ | rimisurato al 554 |
| **Test MCP** | 392 / 392 ✅ | ⚠️ misurato al **549** |
| **macOS x86_64 / aarch64** (`cargo check`) | ✅ 0 errori | rimisurato al 554 |
| **macOS ARM su CI** | ✅ backend `success` | live test: 1 su 4 |
| **macOS Intel su CI** | 🟡 gira dal 544 | fallisce sui live test, come ARM |
| **iOS Simulator** | **1833 / 1834** | l'ultimo rosso chiuso al 553 |
| **`aarch64-apple-ios`** | ✅ compila | dal 542 |
| **Linux aarch64 su CI** | ❌ build fallisce | 43 errori → port scritto al 552, **esito non ancora letto** |
| **Regressioni aperte** | **0** | i rossi residui sono `ios::`, fail-first in corso di un workflow parallelo |

### Copertura per piattaforma

| | Windows x64 | Linux x64 | macOS ARM | macOS Intel | iOS |
|---|---|---|---|---|---|
| Compila | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Eseguito** | ✅ | ✅ | ✅ **CI** | ✅ **CI** | 🟡 Simulator |
| Test live | 67 ¹ | 34 ¹ | **4** (1 passa) | 4 (1 passa) | 0 |
| Breakpoint sw su ARM64 | — | ❌ rifiutato | ❌ rifiutato | — | — |

¹ non rimisurato in questo consolidamento.

---

## 3. Dimensioni

Rimisurate al 556.

| Componente | File | Righe |
|---|---|---|
| `src/*.rs` (primo livello) | 55 | **71 193** |
| ├─ `lib.rs` | | 12 393 |
| ├─ `windows_debugger.rs` | | 8 414 |
| ├─ `linux_debugger.rs` | | 5 675 |
| └─ `macos_debugger.rs` | | 4 741 |
| `src/ios/` (**549** test) | 17 | **33 345** |
| `src/codeview/` | 15 | **19 539** |
| **`rustre-debug` totale** | **87** | **124 077** |
| `rustre-mcp-tools` — `tools/debug.rs` | 1 | 6 872 |

`src/ios` è cresciuto da 30 739 righe / 502 test a **33 345 / 549** in due giri di
workflow.

---

## 4. Iterazioni 540-556

### 516→539: compresse
19 difetti/gap, 3 protezioni, 1 ritirata, 1 misura senza consegna.

### La famiglia «esito affermato, non derivato»
Cinque iterazioni, una regola.

| # | Dove | Cosa affermava |
|---|---|---|
| 540 | `rewind_past_own_breakpoint` | `Ok(Breakpoint)` con il PC lasciato dentro un'istruzione |
| 542a | restore di un breakpoint disabilitato | «step riuscito» con una trappola **armata** |
| 544 | `detach` | `Ack(Ok(()))` letterale — su Windows il target **muore** col debugger |
| 554 | `kill` | idem; su macOS `_already_reaped` era **uno scarto travestito da nome** |
| — | MCP | già onesto dal 536-539: non aveva nulla di veritiero sotto |

La sfumatura che si ripete: **rendere severo alla cieca è un difetto nuovo**.
`ESRCH` su un detach o un kill è l'esito *riuscito* scritto come errore — un
processo già andato non ha più nulla da cui staccarsi né da uccidere. `EPERM` sì:
dice che il target c'è ancora e non è nostro.

### La famiglia «assunzione x86 / elenco di piattaforme»
Sei difetti, una causa: il workspace è stato scritto e verificato **solo su
Windows x86** per tutta la sua vita.

| # | Difetto | Invisibile su |
|---|---|---|
| 542b | `dbg` non legato su iOS → `error[E0423]`, il crate **non compilava** | Windows |
| 542c | 8 `const fn` col corpo `cfg(linux)`; sotto, `ptrace::write` mistipizzata | Windows |
| — | `pyo3` vs Python del runner · `fuser` obbligatorio · `#[path]` in modulo inline | Windows |
| 546 | PC-1 e `0xCC` nei classificatori: **su arm64 nessun breakpoint veniva riconosciuto** | x86 |
| 548 | salva 1 byte, ne scrive 4 → tre byte di `BRK` lasciati nel target | x86 |
| 552 | `PTRACE_GETREGS` e `user_regs_struct.rip` non esistono su aarch64 | x86 |

### La famiglia «il guard non poteva girare»
549 e 553: cinque guard fallivano sul Simulator perché leggevano `src/` a
runtime. `include_str!` non bastava — devono coprire **ogni** file, e una lista a
mano diventa stantia al primo file aggiunto. Un `build.rs` enumera a compile
time. Al 553 si è scoperto che il fix del 549 ne aveva mancato **una seconda
copia** della stessa logica, dentro il corpo di un altro guard: *«two parsers of
one format is how iteration 344's field-shift bug happened»*, scritto da questo
crate su sé stesso.

### 550-551, 555-556: l'infrastruttura, e i suoi difetti
- **550**: Linux non aveva **nessuna CI**. Aggiunti `ubuntu-24.04` e
  `ubuntu-24.04-arm`, e rilassato `kernel.yama.ptrace_scope` — senza, i test live
  non fallirebbero: sarebbero *inutili*.
- **551**: primi 4 test live macOS, in un passo CI con `sudo` isolato.
- **555**: il passo principale li eseguiva **senza** `sudo`, falliva, e il passo
  privilegiato non partiva mai — *riporta un fallimento e trattiene la risposta
  insieme*. Corretto con `--skip live_tests`.
- **556**: due difetti nel workflow del 550, entrambi misurati. Il job x86_64 era
  **cancelled** al timeout di 45 min a metà `Test rustre-mcp-tools` (ora 90), e
  il summary faceva `!= "failure"` — quindi **un job annullato riportava
  successo**. Ora `= "success"`. Il summary macOS aveva già la forma giusta.

### 557 — `pause()` su Windows riportava un breakpoint che non esiste

`classify_event` trasforma ogni `EXCEPTION_BREAKPOINT` in
`StopReason::Breakpoint { bp: new_software(addr) }` — inevitabile lì, è una
funzione libera sull'evento grezzo. Ma nulla a valle correggeva, quindi tre cose
diverse arrivavano al chiamante come «hai colpito un breakpoint software»:
`pause()` (che funziona iniettandone uno con `DebugBreakProcess`), il breakpoint
iniziale che Windows consegna sempre, e un `__debugbreak()` nel codice del
target. Con `enabled: true`, a un indirizzo mai impostato dall'utente.

**Il primo tentativo era troppo largo, e la misura l'ha fermato.** Riclassificare
in `StopReason::Exception` ha fatto cadere **sei test live** più
`initial_stop_tid` dell'MCP: aspettano un `Breakpoint` per sapere che il processo
è fermo e pronto, e hanno ragione — Windows *consegna* letteralmente un
breakpoint lì.

La variante non era la bugia: **il record lo era**. Fix a raggio zero in
`enrich_event_breakpoint`, che è il primo punto ad avere la tabella dei piantati:
`label` che dice cosa è davvero, ed `enabled: false` perché un breakpoint mai
piantato non può essere armato. `original_byte` e `hit_count` erano già veritieri
(`None` e `0`); ora la ragione è detta invece che lasciata da dedurre da due
campi assenti.

MCP: nessuna modifica: `"stop_reason": format!("{:?}", ev.reason)` include già il
`Debug` di `Breakpoint`, quindi l'etichetta raggiunge l'utente. Verificato, non
assunto.

### 558 — i test live chiedevano `rax` a un backend che risponde `x0`

Il port del 552 ha portato aarch64 da **43 errori di build** a **1893 test passati,
13 falliti**, tutti live: gli unit test passano tutti, il port è strutturalmente
corretto. Il triage dei 13 dice che la maggioranza non sono difetti del backend:

- **6** rifiuti attesi — `Unsupported("software breakpoints … x86 int3 …")` e
  `RegisterError("unknown register dr0")`: le difese di 548 e 552 che funzionano;
- **5** test scritti per x86 che chiedono `rax`/`rip` a un register set che
  pubblica `x0`-`x30`/`sp`/`pc`/`pstate`, e piantano breakpoint a indirizzi non
  allineati a 4 byte;
- **2** reali e inspiegati.

Corretti i nomi dei registri (il PC via `instr_step::pc_key`, non una quinta
grafia). **Non** corretti i 16 punti di chiamata a `set_breakpoint`: silenziare
11 fallimenti attesi non insegna nulla. Reso invece **preciso il permesso** sulla
riga aarch64 — il job si chiama ora `11 expected, 2 unexplained`, così il
prossimo delta è leggibile.

### 559 — l'unwinder condiviso usava un puntatore firmato come indirizzo

Uno dei due «reali» del 558. La CI ARM:

```
unwound frame pc 0x77aba8e6a55c0c should fall inside a loaded module
```

55 bit, sopra l'intervallo utente a 48: **un puntatore firmato, non un
indirizzo**. Su AArch64 con branch protection — norma su arm64e Apple, sempre più
comune su Linux — il `LR` salvato a `[fp+8]` porta un PAC nei bit alti, e
`memory_layout_view` (l'unwinder **condiviso dai tre backend**) lo usava grezzo.
Ogni frame dopo il primo cadeva in nessun modulo, su entrambe le piattaforme ARM.

`strip_pac` esisteva già in `ios/arm64.rs` — aritmetica pura che gira su ogni
host — e l'unico consumatore era il runtime ObjC.

Il fix strippa **solo** quando il grezzo non risolve e lo strippato sì. Non è
prudenza: `strip_pac` codifica lo split utente a 47 bit di **Apple** e Linux
AArch64 è comunemente a 48, quindi dove la maschera è sbagliata lo strippato non
risolve e nulla cambia. È la proprietà che permette di spedirlo **senza una
macchina ARM su cui provarlo**.

⚠️ **Nota di metodo**: i primi due rossi di questo round erano il guard del
*fixture*, non l'asserzione. Il verde è arrivato senza che il difetto fosse mai
stato visto. Ho revertito il fix per misurare il rosso vero
(`[48004424077312, 33684264141020172]` — il puntatore firmato conservato tale e
quale) e poi ripristinato. **Un test che passa senza aver mai fallito non
dimostra nulla**, ed è la contestazione che un revisore avversariale aveva già
mosso al primo giro Apple.

---

## 5. Difetti aperti — dichiarati, non nascosti

| Cosa | Dove | Perché non è chiuso |
|---|---|---|
| **`task_for_pid` richiede root** | macOS | Misurato al 555. Non è un difetto da correggere: è un vincolo della piattaforma da **documentare** verso l'utente. Serve decidere se il prodotto chiede l'entitlement o l'esecuzione privilegiata. ⚠️ decisione dell'utente. |
| **Port aarch64 Linux** | Linux | Scritto al 552; l'esito CI **non è ancora stato letto**. Fino ad allora non è verificato. |
| **Breakpoint sw su ARM64** | tutti e 3 | `X86_TRAP_BYTE_IS_VALID_HERE`. Il 548 ha tolto il difetto che lo rendeva necessario; resta da verificare il port del 552. |
| **Registri di debug su ARM64** | Linux | `Unsupported` esplicito dal 552: `NT_ARM_HW_BREAK`/`NT_ARM_HW_WATCH` sono un sottosistema, non una rinominazione. |
| **Indirizzo faultante** | macOS | Via più leggera identificata (stato di eccezione del thread: `__far`/`__faultvaddr` via `thread_get_state`), **non implementata**: `mach2` non espone le struct e senza poter eseguire un offset sbagliato darebbe un indirizzo plausibile e falso — peggio di `None`. |
| **Eventi thread** | macOS | Nessun equivalente di `PTRACE_O_TRACECLONE`. |
| **Canonico del frame pointer** | crate | `x29` vs `fp`. Il 552 pubblica **entrambi** per non decidere di nascosto. ⚠️ decisione dell'utente. |
| **iOS su hardware** | infrastruttura | Non ottenibile su Actions: serve un device fisico e un runner self-hosted. |
| **`pyo3 0.23`** | workspace | Il pin a 3.13 rende il build riproducibile; alzarlo richiede l'upgrade su tre crate. |
| **14 file `.bak*`** | `src/` | Decisione dell'utente. |

---

## 6. Il fronte Apple: due giri di workflow

**Giro 1** — 16 superfici, ogni segnalazione a **tre scettici col compito di
confutarla**: 34 trovate, **24 sopravvissute, 10 buttate**. Poi un agente per
file, ognuno rivisto da un avversario: **26 difetti chiusi su 13 file**.

Due file bocciati «dubbio», e i revisori avevano ragione su entrambi — guard che
vivevano solo in uno scratchpad (chiuso al 545), un test che cristallizzava
`Return { reg: 31 }` per `retaa` quando il ritorno passa da **x30** (chiuso), una
motivazione tecnica **rovesciata** (chiusa al 546).

**Giro 2** — in corso: 36 segnalazioni dall'audit, verifica avversariale non
conclusa.

---

## 7. Lezioni di metodo

1. **Un test che si *appende* quando il codice è sbagliato non è un test.**
2. **Un commento che giustifica l'azione non giustifica lo scarto del suo
   esito** — vista 7 volte.
3. **Un'eccezione motivata va ristretta al caso che la motiva.**
4. **Quando un silenzio non si può trasformare in errore, cercare un chiamante
   diverso che possa rispondere** (541).
5. **Leggere il consumatore, non provare varianti del produttore** (528).
6. **Misurare prima di correggere.**
7. **Un guard ancorato a una stringa è fragile** (540, 546).
8. **Una funzione che ritorna `()` non ha dove mettere un fallimento** (540).
9. **Un numero va ricontrollato quando lo si eredita** (540).
10. **Rendere un controllo severo alla cieca è un difetto nuovo** (544, 554).
11. **Un elenco di piattaforme si verifica compilando, non rileggendo.**
12. **L'assenza di un fallimento non è la presenza di un successo** (556): un job
    in coda per sempre non è mai rosso, e uno *annullato* passava per verde.
13. **Un guard può portare il difetto che dovrebbe prevenire** (546).
14. **Quando una difesa sembra stantia, cercare cosa sta difendendo** (548): il
    rifiuto ARM64 era l'ultima cosa fra il debugger e la corruzione del target.
15. **Un guard che si salta non è un guard** (549).
16. **Correggere una copia su due lascia il difetto** (553).
17. **Riportare un fallimento e trattenere la risposta è la disposizione
    peggiore** (555): il passo che doveva dare la risposta non partiva.
18. **Misurare un albero in movimento non è misurare** (551): tre esiti
    incompatibili sullo stesso codice, risolti solo da un worktree isolato.
