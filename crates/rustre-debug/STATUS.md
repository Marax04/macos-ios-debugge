# STATUS — `rustre-debug`

> **Cruscotto del debugger.** Aggiornato a **ogni iterazione**. Ogni numero qui è
> **misurato**, mai stimato: se una cosa non è stata misurata, è scritto che non
> lo è stata.
>
> **Ogni 4 iterazioni questo file va riscritto da zero**, non solo esteso: il
> semaforo e le dimensioni si rimisurano, i difetti chiusi escono dalla tabella
> degli aperti, le iterazioni vecchie si comprimono in una riga di totale.
>
> Ultimo aggiornamento: **iterazione 560** · 2026-08-15
> **Riscrittura completa.** Precedente al 556. Prossima: iterazione 564.

---

## 1. Dove siamo

**Tutte e quattro le piattaforme sono ora ESEGUITE, non solo compilate.**

| | Windows x64 | Linux x64 | macOS ARM | macOS Intel | iOS Sim | Linux ARM |
|---|---|---|---|---|---|---|
| Compila | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ ¹ |
| **Eseguito** | ✅ | ✅ | ✅ CI | ✅ CI | ✅ CI | ✅ CI |
| Suite | **1969/1969** | **1952/1952** | success | success | success | 1893 + 13 live |

¹ Dal 552. Prima falliva il **build** con 43 errori.

Il limite dichiarato del progetto per 539 iterazioni — «macOS non è mai stato
eseguito» — non era un difetto da correggere: il repo **non aveva nessun commit
né remote**, quindi il workflow macOS esisteva e non era mai partito.

---

## 2. Semaforo

| Indicatore | Valore | Note |
|---|---|---|
| **Test Windows** | **1969 / 1969** ✅ | rimisurato al 559; **zero** rossi |
| **Test Linux** (WSL, seriale) | **1952 / 1952** ✅ | rimisurato al 559 |
| **Test MCP** | 392 / 392 ✅ | rimisurato al 559 |
| **macOS x86_64 / aarch64** (`check`) | ✅ 0 errori | rimisurato al 559 |
| **CI macOS ARM** | ✅ job intero | backend + MCP su hardware Apple |
| **CI iOS Simulator + device triple** | ✅ | dal 553 |
| **CI Linux aarch64** | 1893 passati, 13 live | 11 attesi · 2 reali, **entrambi chiusi al 559-560** |
| **Regressioni aperte** | **0** | |

### Copertura live

| | Windows | Linux | macOS | iOS |
|---|---|---|---|---|
| Test live | 67 ¹ | 34 ¹ | **4** | 0 |
| di cui passano | 67 | 34 | **1** | — |

¹ non rimisurato in questo consolidamento.

Su macOS solo `launch_runs_a_child_to_exit` passa: `fork` + `PT_TRACE_ME` +
`execvp` e il ciclo di wait funzionano **senza privilegi**, tutto ciò che
richiede una task port Mach no — `task_for_pid` risponde `kern_return 5` senza
root o l'entitlement. **È un vincolo di deployment da documentare, non un
difetto da correggere.**

---

## 3. Dimensioni

Rimisurate al 560.

| Componente | File | Righe |
|---|---|---|
| `src/*.rs` (primo livello) | 55 | **71 436** |
| ├─ `lib.rs` | | 12 393 |
| ├─ `windows_debugger.rs` | | 8 518 |
| ├─ `linux_debugger.rs` | | 5 724 |
| ├─ `macos_debugger.rs` | | 4 741 |
| └─ `memory_layout_view.rs` | | 2 033 |
| `src/ios/` (**576** test) | 17 | **34 778** |
| `src/codeview/` | 15 | **19 539** |
| **totale** | **87** | **125 753** |

`src/ios` è passato da 30 739 righe / 502 test a **34 778 / 576** in due giri di
workflow.

---

## 4. Le tre famiglie di difetti

I ventitré difetti di 540-560 non sono indipendenti.

### A. «Esito affermato, non derivato» — 6 iterazioni
540 rewind · 542a restore · 544 `detach` · 554 `kill` · 557 `pause`.
Tutti rispondevano con un letterale dopo aver scartato l'esito della syscall.

La sfumatura che si ripete: **rendere severo alla cieca è un difetto nuovo**.
`ESRCH` su un detach o un kill è l'esito *riuscito* scritto come errore — un
processo già andato non ha più nulla da cui staccarsi né da uccidere.

Il 557 aggiunge il rovescio: **la variante non era la bugia, il record lo era**.
Riclassificare lo stop faceva cadere sei test live che avevano ragione; bastava
smettere di affermare che il breakpoint fosse nostro.

### B. «Assunzione x86 / elenco di piattaforme» — 8 difetti
Una causa sola: il workspace è stato scritto e verificato **solo su Windows x86**
per tutta la sua vita.

| Difetto | Invisibile su |
|---|---|
| `pyo3` vs Python del runner · `fuser` obbligatorio · `#[path]` in modulo inline · `const fn` con corpo `cfg(linux)` | Windows |
| 546 PC-1 e `0xCC` nei classificatori — **su arm64 nessun breakpoint riconosciuto** | x86 |
| 548 salva 1 byte, ne scrive 4 → tre byte di `BRK` lasciati nel target | x86 |
| 552 `PTRACE_GETREGS` e `user_regs_struct.rip` inesistenti | x86 |
| 559 PAC nell'unwinder condiviso — **ogni frame dopo il primo in nessun modulo** | x86 |

### C. «Lo strumento di misura era sbagliato» — 7 difetti
Ogni volta che ho aggiunto una misura, il primo risultato è stato che la misura
stessa era difettosa. Ed è il gruppo che ha insegnato di più.

| # | Cosa |
|---|---|
| 549/553 | guard che leggevano `src/` a runtime; il fix del 549 ne ha mancato **una seconda copia** |
| 550/556 | il job x86_64 **cancellato** al timeout, e il summary lo firmava `success` perché testava `!= failure` |
| 555 | il passo principale eseguiva i test live senza `sudo`: **riportava un fallimento e tratteneva la risposta insieme** |
| 544-556 | `macos-13` ritirato: l'etichetta si legge e non viene **mai schedulata** |
| 558 | i test live chiedevano `rax` a un backend che risponde `x0` |
| 560 | il test multi-thread prendeva il **primo stop qualunque**, e l'iterazione 526 gli aveva cambiato il flusso di eventi sotto |

---

## 5. Iterazioni 556-560

### 557 — `pause()` riportava un breakpoint inesistente
Vedi famiglia A. Fix a raggio zero: `label` + `enabled: false` in
`enrich_event_breakpoint`, il primo punto che ha la tabella dei piantati.
MCP invariato: `stop_reason` è il `Debug` dell'intera ragione, quindi
l'etichetta arriva già. Verificato, non assunto.

### 558 — triage dei 13 rossi ARM
6 rifiuti attesi · 5 test x86 · 2 reali. Corretti i nomi dei registri via
`instr_step::pc_key`. **Non** toccati i 16 punti di `set_breakpoint`: silenziare
11 fallimenti attesi non insegna nulla. Il job CI è rinominato
`11 expected, 2 unexplained` — il delta del prossimo run è ora leggibile.

### 559 — PAC nell'unwinder condiviso
Strippa **solo** quando il grezzo non risolve e lo strippato sì: `strip_pac`
codifica lo split a 47 bit di **Apple** e Linux AArch64 è comunemente a 48,
quindi dove la maschera è sbagliata non cambia nulla. È la proprietà che lo rende
spedibile **senza una macchina ARM su cui provarlo**.

⚠️ Il test è diventato verde **senza che il difetto fosse mai stato visto**: i due
rossi precedenti erano il guard del *fixture*, per due errori miei. Ho revertito
il fix per misurare il rosso vero e poi ripristinato.

### 560 — un test che passava per tempismo
`secondary_thread_is_really_traced_and_controllable` prendeva il primo stop e
enumerava subito. Corretto fino all'**iterazione 526**, che ha iniziato a
riportare `ThreadCreate`: da allora il primo stop è la nascita del worker, e il
test enumerava `/proc/<pid>/task` nell'istante del clone. Su x86 la voce c'è
già; su aarch64 no.

**Nessuno ha rotto questo test**: un'iterazione ha cambiato il flusso di eventi
sotto di lui, legittimamente, e lui ha continuato a passare per un accidente di
scheduling. Ora salta le nascite thread e attende lo stop della fixture.

### 561 — RITIRATO, ed è la voce più istruttiva di questa sezione

Avevo visto `combined_dr7` nel corpo di `macos_debugger::set_watchpoint_sized`,
concluso «registri x86», e ristretto il gate di architettura togliendo
`aarch64`. Avevo anche scritto un guard che codificava quella conclusione.

**Era falso.** Il guard preesistente
`the_macos_backend_reaches_the_arm64_watchpoint_registers` mi ha fermato: macOS
dichiara `ARM_DEBUG_STATE64 = 15`, ha un controllo a compile time sul conteggio
di parole della sua `ArmDebugState64`, e possiede
`dr_slot_from_arm64_watchpoint` / `arm64_watchpoint_from_dr_slot`.

Quel `dr7` **non è x86**: è la rappresentazione **condivisa** dei watchpoint di
questo crate, e macOS la traduce nelle coppie `DBGWVR`/`DBGWCR`. Il «fix»
rimuoveva supporto AArch64 funzionante — e il guard che l'accompagnava era
peggio, perché avrebbe impedito per sempre di riconoscere che quel percorso
esiste.

Entrambi ritirati; `git diff` su quei due file è tornato vuoto.

**L'errore ha un nome: è la lezione 14 violata al contrario.** Al 548 quella
lezione mi aveva salvato dal togliere il rifiuto dei breakpoint ARM64, che stava
difendendo il target dalla corruzione. Qui ho fatto lo speculare: **ho letto un
nome come se fosse un'implementazione**, senza controllare se fosse
un'astrazione.

Merito al codice: quel guard è scritto per fallire se qualcuno rimuove la
traduzione ARM64 — e ha fallito su di me, che è esattamente il suo mestiere. Non
c'è divergenza fra backend da sanare: macOS è **più avanti** degli altri due, che
gateano su x86 perché quella traduzione non ce l'hanno.

### 562 — i test live asserivano il byte di trappola x86 scritto a mano

Lo stesso difetto del **548** — *«salva 1 byte, ne scrive 4»* — nello strato dei
test, che non ha mai seguito quel fix. Cinque siti in `linux_debugger.rs`
leggevano **un** byte e lo confrontavano con un `0xCC` letterale: su AArch64
asserirebbero l'`int3` x86 contro un `BRK` da quattro byte.

Ora derivano da `host_trap_bytes()`, come fa la produzione dal 548. Il confronto
del ripristino è esteso a **tutti** i byte della trappola: verificarne uno solo
passerebbe su ARM mentre tre byte di `BRK` restano nel target — esattamente il
difetto che il 548 ha chiuso nel percorso di produzione.

Aggiunto `plant_software_bp`, che **asserisce il rifiuto documentato** invece di
saltare: un test che uscisse in silenzio resterebbe verde su un backend che
avesse ricominciato ad accettare una richiesta che non sa servire.

Riduce da 11 a ~5 i fallimenti attesi della riga CI `Linux aarch64`; i restanti
sono i test dei registri di debug, che ricevono l'`Unsupported` del 552.

### 563 — gli ultimi test che assumevano x86, e il flag che ora si può togliere

I due test dei registri di debug (`hardware_debug_registers_*`) sono interamente
su `DR0`-`DR7`: non hanno equivalente ARM da esercitare con lo stesso codice.
Aggiunto `debug_registers_available`, che **asserisce il rifiuto documentato**
invece di saltare — AArch64 i breakpoint hardware ce li ha, ma dietro
`NT_ARM_HW_BREAK`/`NT_ARM_HW_WATCH`, e il 552 ha fatto sì che quella via
rispondesse `Unsupported` invece di uno zero plausibile. Un test che uscisse in
silenzio resterebbe verde se quel rifiuto venisse sostituito da una risposta
inventata, che è il fallimento che esiste per prevenire.

Verificato su x86: entrambi passano, comportamento invariato.

**Con questo la riga CI `Linux aarch64` dovrebbe essere verde**: i due «reali»
chiusi al 559 e 560, gli attesi resi consapevoli dell'architettura al 558, 562 e
563.

Il `continue-on-error` **resta finché il prossimo run non lo dimostra**.
Toglierlo adesso renderebbe la CI rossa per una mia previsione invece che per un
difetto — e il punto di quella riga è misurare, non prevedere.

---

## 6. Il fronte Apple: tre giri di workflow

| Giro | Trovati | Confermati | Confutati | Chiusi |
|---|---|---|---|---|
| 1 | 34 | 24 | **10** | 26 su 13 file |
| 2 | 36 | 27 | **9** | 22 su 9 file |
| 3 | in corso — prima lente: **meta-revisione delle 48 correzioni dei giri 1-2** | | | |

Il valore non è nel conteggio ma nelle **bocciature**. Al giro 1 due file sono
tornati «dubbio» e i revisori avevano ragione: guard che vivevano solo in uno
scratchpad, un test che cristallizzava `Return { reg: 31 }` per `retaa` quando il
ritorno passa da **x30**, e una motivazione tecnica **rovesciata**.

Al giro 2 il rapporto migliore è venuto da un agente che ha trovato i propri
difetti **già corretti** da un altro, ha rifiutato di rivendicarli, li ha
revertiti per misurare il rosso, li ha ripristinati, e ha lasciato aperto un
irrigidimento che non poteva giustificare con un test rosso — *«inventarne uno
sarebbe teatro»*.

---

## 7. Difetti aperti — dichiarati, non nascosti

| Cosa | Dove | Perché non è chiuso |
|---|---|---|
| **`task_for_pid` richiede root** | macOS | Vincolo di piattaforma, misurato al 555. Serve decidere se il prodotto chiede l'entitlement o l'esecuzione privilegiata. ⚠️ **decisione dell'utente**. |
| **Breakpoint sw su ARM64** | tutti e 3 | `X86_TRAP_BYTE_IS_VALID_HERE`. Il 548 ha tolto il difetto che lo rendeva necessario e il 552 ha portato i registri; resta da esercitarlo. |
| **16 `set_breakpoint` nei test live** | Linux | Assumono x86. Meccanico, non fatto: vedi 558. |
| **Registri di debug su ARM64** | Linux | `Unsupported` esplicito dal 552: `NT_ARM_HW_BREAK`/`NT_ARM_HW_WATCH` sono un sottosistema, non una rinominazione. |
| **Indirizzo faultante** | macOS | Via più leggera identificata (`__far`/`__faultvaddr` via `thread_get_state`), **non implementata**: `mach2` non espone le struct e senza poter eseguire un offset sbagliato darebbe un indirizzo plausibile e falso — peggio di `None`. |
| **Eventi thread** | macOS | Nessun equivalente di `PTRACE_O_TRACECLONE`. |
| **Canonico del frame pointer** | crate | `x29` vs `fp`. Il 552 pubblica **entrambi** per non decidere di nascosto. ⚠️ **decisione dell'utente**. |
| **iOS su hardware** | infrastruttura | Non ottenibile su Actions: serve un device fisico e un runner self-hosted. |
| **`pyo3 0.23`** | workspace | Il pin a 3.13 rende il build riproducibile; alzarlo richiede l'upgrade su tre crate. |
| **14 file `.bak*`** | `src/` | ⚠️ **decisione dell'utente**. |

---

## 8. Lezioni di metodo

1. **Un test che si *appende* quando il codice è sbagliato non è un test.**
2. **Un commento che giustifica l'azione non giustifica lo scarto del suo esito**
   — vista 8 volte.
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
12. **L'assenza di un fallimento non è la presenza di un successo** (556).
13. **Un guard può portare il difetto che dovrebbe prevenire** (546).
14. **Quando una difesa sembra stantia, cercare cosa sta difendendo** (548, 557).
15. **Un guard che si salta non è un guard** (549).
16. **Correggere una copia su due lascia il difetto** (553).
17. **Riportare un fallimento e trattenere la risposta è la disposizione
    peggiore** (555).
18. **Misurare un albero in movimento non è misurare** (551).
19. **Un test che passa senza aver mai fallito non dimostra nulla** (559): se il
    fix è già presente, revertirlo per vedere il rosso e poi ripristinarlo.
20. **Un test può passare per tempismo** (560): nessuno lo rompe, cambia il
    flusso di eventi sotto di lui e continua a passare su una piattaforma sola.
21. **Un nome non è un'implementazione** (561, ritirato): `dr7` in un corpo
    macOS sembrava «registri x86» ed era la rappresentazione CONDIVISA, tradotta
    in `DBGWVR`/`DBGWCR`. È la lezione 14 al contrario — lì una difesa sembrava
    obsoleta e proteggeva qualcosa, qui un'implementazione sembrava sbagliata ed
    era un'astrazione. In entrambi i casi la domanda è la stessa: **cosa c'è
    davvero dietro il nome che sto per cambiare?**
