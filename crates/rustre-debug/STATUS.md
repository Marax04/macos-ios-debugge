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
