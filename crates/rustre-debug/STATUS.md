# rustre-debug — stato misurato

> **Regola.** Ogni 4 iterazioni questo file va riscritto DA ZERO. È un cruscotto,
> non un registro. Precedente riscrittura: 618. Questa: **624**, aggiornata al **625**, con due
> iterazioni di ritardo — annotate, non nascoste.
>
> **Ogni numero è misurato.** «Non dimostrato» = nessuna macchina raggiungibile
> ha risposto: lacuna dichiarata, non dettaglio.
>
> Ogni misura è presa in un `git worktree` su `main` coi **soli hunk miei**
> applicati sopra. L'albero condiviso contiene in permanenza lavoro non
> committato di altri attori e a volte non compila; misurarlo non è misurare.

---

## 1. Semaforo

| Dove | Verificato come | Esito |
|---|---|---|
| Windows x86_64 | suite locale, worktree isolato | **2096 / 1** |
| Linux x86_64 | WSL, `--test-threads=1` | **2079 / 1** |
| Darwin ×2 | `cargo check --target` | **0 errori** |
| MCP | Windows | **399 / 1** |
| Windows ARM64 | CI `windows-11-arm` | compila (602, 606); non riconfermato dopo il 612 |
| Linux aarch64 | CI `ubuntu-24.04-arm` | 3 fallimenti al 608; **i fix 607/608/609 non sono mai stati rimisurati** |
| macOS Intel / Apple Silicon | CI | suite e live test **verdi** |
| iOS Simulator | CI `macos-14`, arm64 reale | **verde** |
| iOS device | CI | compila e **linka** i test; non esegue (serve hardware) |

I due **1** sono noti e dichiarati: il rosso del debugger è
`ios::apple_debugger::step_out_leaves_the_frame_when_lr_no_longer_holds_the_return_address`
(§4), quello dell'MCP è il cricchetto dei fabbricatori (§4).

## 2. ⚠ L'albero condiviso non è uno stage — è già costato la build

Al 622 il commit `956a6feea` («clippy: five lint classes down») ha incluso,
insieme al proprio lavoro, il **mio 622 a metà** preso dall'albero condiviso:
firma nuova con i `return None` vecchi, e una `DebugError::MemoryAccess`
inesistente. **`main` non compilava.** Nei tre backend quel commit non conteneva
nessuna modifica clippy propria — ogni riga era mia, trapelata — e ha anche
riportato `STATUS.md` al 618, annullando 619, 620 e 621.

Lo stesso rischio, visto dall'altro lato, era già stato annotato al 617: allora
trovai l'**indice** dell'albero principale che conteneva un'**inversione** del mio
stesso commit, pronta a essere committata dal prossimo attore.

Da qui la regola operativa: committare da un `worktree` contenente `main` più i
soli hunk propri, far avanzare il branch con `update-ref` senza toccare l'albero,
e azzerare l'indice sui propri file subito dopo.

## 3. Le tre famiglie di difetti che questo crate produce

1. **Un'assenza che si traveste da risposta**: `unwrap_or(0)`, `.ok()`,
   `unwrap_or_default()`, un `Option` che collassa «non l'ho trovato» con «no»,
   un `bool` per tre esiti. È la famiglia più numerosa, e la cura è sempre la
   stessa — **un terzo stato**. Il crate ne ha ora cinque, tutti nati da un
   difetto misurato: `DebugRegisterState` (619), `CapabilityStatus` (621),
   `StepOff` (622), `capability_refusal` (620) e `u64_from_le_prefix` (624).
2. **Logica condivisa che deriva**: fra i quattro backend, fra backend e MCP,
   fra una capacità DICHIARATA e il codice che la nega. Otto round di fila hanno
   trovato questo — tre copie con tre risposte diverse (612, 614), due tabelle
   per una decisione (616), **quattro** elenchi degli stessi nomi (618), tre
   copie di un `panic` mentre la quarta era corretta (624).
3. **Un'assunzione sbagliata su CHI è la macchina**: x86 assunto dove gira ARM
   (byte di trappola, PAC, slot, trap flag), e — più sottile — l'architettura
   dell'**host** usata per interpretare i registri del **target** (615, 616).

## 4. Difetti aperti — dichiarati

| Cosa | Dove | Stato |
|---|---|---|
| **Il mock non serve via `m` le proprie scritture di stack** | iOS, `mock_debugserver.rs` | **CAUSA RADICE TROVATA AL 625, misurata con una sonda.** In `step_out` sul test rosso: `target = 0x0`, e leggendo 16 byte al frame pointer arrivano **tutti zeri**, mentre `read_memory` sullo stesso percorso restituisce correttamente il **testo** (`fd 7b bf a9` = `0xA9BF7BFD`). L'interprete esegue davvero — `sp` passa da `…ffe0` a `…fff0`, cioè `ldp` è stato eseguito — e il gestore `STP_FP_LR_PRE` scrive correttamente `x29` e `x30`. Quindi le letture `m` e la memoria dell'interprete **non sono la stessa istanza**. Ne dipendono **due** test: `step_out_leaves_the_frame…` (rosso su main) e `step_out_hands_back_a_fault…`. Chi lo chiude probabilmente li chiude entrambi |
| **iOS non onora `Breakpoint::condition`** | iOS | `condition_allows_stop` compare 5 volte in ciascuno dei tre backend desktop e **0** volte in `apple_debugger.rs`, mentre il tipo documenta «only stop when this evaluates to true». Su iOS un breakpoint condizionale si ferma a ogni hit |
| **13 difetti iOS confermati** | iOS | verificati da tre scettici al giro 8, fix mai eseguito per errori API 529; il retry ne ha recuperati 5 |
| **Cricchetto MCP 172/168** | tutti | **non mio**: dei 172 fabbricatori, **zero** hanno prefisso `debug_`/`linux_`/`macos_`/`ios_`/`win_`. Era 170 al 605. Da riportare al proprietario, **non** da far tacere alzando il soffitto |
| **PAC nell'unwinder** | Linux ARM | 573 e 591 erano codice morto; il 607 lo legge per primo. **Mai rimisurato in CI** |
| **2 test sui registri di debug** | Linux ARM | `NT_ARM_HW_WATCH` sembra fallire su quel runner: da capire, non da indovinare |
| **Single step su Windows ARM** | Windows | rifiutato esplicitamente (606): il meccanismo AArch64 non è implementato e inventarlo sarebbe peggio |
| **Watchpoint hw su Windows ARM** | Windows | il CONTEXT ha `Bcr`/`Bvr`/`Wcr`/`Wvr` (2 slot, non 4). Dichiarato assente (598) e **rifiutato a runtime con quella ragione** (620) |
| **Eventi di thread** | macOS, iOS | Mach e RSP non li consegnano. Dichiarati assenti col motivo |
| **`task_for_pid` root** | macOS | ⚠️ **decisione dell'utente** |
| **iOS su hardware** | infrastruttura | i runner ospitati non hanno iPhone. Il simulatore però è arm64 REALE |
| **14 file `.bak*`** | `src/` | ⚠️ **decisione dell'utente** |

## 5. Chiuso di recente, con la misura

- **Un indirizzo di ritorno nullo veniva inseguito fino alla morte del processo**
  (625). Ogni backend legge otto byte da `[fp+8]` e li passa a `run_to_return`
  come indirizzo a cui fermarsi; nessuno chiedeva se il valore fosse usabile, e
  **zero** è l'unico che di sicuro non lo è. `run_to_return_step` confronta poi
  `pc == 0`, che non si avvera mai, quindi il ciclo fa single step finché il
  processo **esce** e quell'uscita viene riportata come esito dello step-out: si
  chiede di uscire da una funzione e il debugger esegue il programma fino alla
  fine, dicendo che ha funzionato. Il crate conosceva già la regola altrove — il
  `validate` dell'unwinder rifiuta `pc == 0` con «null return address (end of
  stack)». Applicato ai **tre backend desktop**; su iOS è deliberatamente
  **rimandato**, perché lì scatterebbe prima che due test possano esercitare ciò
  che verificano, portando `main` da un rosso a due (§4, causa radice del mock).

- **Una lettura corta mandava in panic invece che in errore** (624). `step_out`
  legge 8 byte per l'indirizzo di ritorno salvato e può riceverne meno — bordo
  di pagina, stack parzialmente mappato, target morto a metà chiamata. I tre
  backend desktop scrivevano `return_addr_bytes[..8].try_into().map_err(…
  "step_out: short read")`: un guard il cui messaggio nomina esattamente quel
  caso e che **non può mai essere raggiunto**, perché lo slice va in panic prima.
  E un panic in un debugger non è uno step fallito: risale fuori, e nell'MCP
  server porta via **tutte** le sessioni, non solo questa. Il backend iOS aveva
  già la forma corretta, `.get(..8)`, due file più in là.
- **Una foglia che non alloca stack ora si può srotolare** (623). `validate`
  pretendeva che `sp` crescesse **strettamente**; una foglia frameless con
  stack-size 0 lascia `sp` invariato e l'indirizzo di ritorno in `lr`. Ogni
  backtrace preso lì dentro si fermava a profondità 1, con tre rifiuti tutti
  plausibili. Ora `sp` non può **calare** e un passo senza progresso — stesso pc
  **e** stesso sp — resta rifiutato.
- **Uno step fallito non è più «non c'era nessuna trappola»** (622). `None`
  significava sette cose, due delle quali volevano la gestione opposta: dopo un
  fallimento la trappola è già riarmata e il thread fermo, quindi il secondo step
  eseguiva l'`int3` — l'esito che la doc di `single_step` cita come la ragione
  per cui quel meccanismo esiste. Specularmente, uno step **riuscito** veniva
  buttato se il ripiantamento falliva, e il thread avanzava di due istruzioni.
- **Il rifiuto del 620 non poteva essere disattivato da un refuso** (621).
- **Una capacità dichiarata assente ora viene RIFIUTATA con la sua ragione**
  (620), letta dalla stessa lista che la pubblica.
- **Un `dr7` assente non è più un thread disarmato** (619): il lettore AArch64 di
  Windows non pubblica affatto `dr7`, quindi ogni thread risultava pulito sempre.
- **Condizioni sui breakpoint: cinque nomi mancanti** (618) — `sil`, `dil`,
  `bpl`, `spl`, `eip`. Una condizione che ne nominava uno non valutava e il
  target si fermava a **ogni** hit.
- **`pc`/`sp`/`fp` seguono il TARGET, non il build** (615, 616), in entrambe le
  direzioni.
- **Nomi di registro stretti in lettura e scrittura** (613, 614).
- **Scritture a `fp`/`lr`/`x29`/`x30` non più scartate** (612).
- **iOS: `fp` e `lr` non arrivavano mai al device** (617).
- Più indietro: breakpoint software su macOS (579), watchpoint e breakpoint
  hardware ARM64 Linux (570, 571, 589, 594), indirizzo di fault su macOS (595),
  CI Windows (597), backend Windows che compila per ARM64 (602, 606), sei tool
  MCP Linux riparati (605).

## 6. iOS — giri avversariali

| Giro | Agenti | Confermati | Chiusi |
|---|---|---|---|
| 6 | 77 | 9 | **9** |
| 7 | 68 | 12 | **12** |
| 8 | 74 | 15 | **2** (13 agenti morti su errori server) |
| 8 (retry) | 64 | 5 | **5** |
| 9 | 62 | 12 | **12** |

## 7. Lezioni di metodo

1. **Misurare il rosso PRIMA.** Se passa al primo colpo, **perturbare** — e
   **ripristinare**: al giro 8 è stata trovata una riga di produzione lasciata
   perturbata da un round precedente, col marcatore ancora attaccato.
2. Un rosso da *compilazione* è il tipo debole: dimostra che manca una funzione,
   non che il comportamento fosse sbagliato.
3. **Il rosso misurato smentisce spesso quello previsto** (613, 623): si corregge
   la frase, non la misura.
4. **Contare quante cose significa un `None`** (622): sette, in una funzione, e
   due volevano la gestione opposta.
5. **Un guard che può fallire PASSANDO è peggio di nessun guard** (621), perché
   gli si crede. E **un guard che sorveglia la PRESENZA non vede la COMPLETEZZA**
   (618): una lista vuota lo soddisfa.
6. **Un guard può essere irraggiungibile** (624): il `map_err` che nominava la
   lettura corta stava dopo lo slice che andava in panic. Scrivere la gestione
   non è averla.
7. **Due implementazioni della stessa decisione: farle CONCORDARE, non scegliere
   a occhio** (616, 618). Nessuna verità esterna serve: se il codice si
   contraddice, un lato sbaglia.
8. **Correggere una copia su tre lascia il difetto** — e a volte la copia giusta
   è già nel repo, in un altro backend (617, 624).
9. **Un rifiuto esplicito NON è un difetto** (606, 601) — **ma verificane la
   PREMESSA** (614). Distinguere i due casi è il giudizio che serve.
10. **Una capacità DICHIARATA va anche IMPOSTA** (620): fra dichiarare e imporre
    c'è la stessa distanza che fra un commento e un test.
11. **Il difetto sta spesso nella FRASE** (612, 614, 617), e **un mio fix può
    rendere FALSA la frase di un altro** (617).
12. **`native_arch()` risponde all'HOST** (615): chiedersi *di chi* è
    l'architettura rivela il difetto.
13. **Un file `cfg`-gated non è verificato dalla suite che non lo compila** (611),
    e **un fix può essere giusto e MORTO** (573, 591).
14. **Non copiare un FILE intero da un albero condiviso per misurare** (617,
    619): si importa il lavoro non committato di altri e il rosso sembra proprio.
    Si applica il proprio **hunk** su `main`.
15. **Attribuire con PROVA, nelle due direzioni** (622): il modo più netto è
    chiedersi se il test **esistesse** nel proprio ultimo verde.
16. **Sondare batte dedurre** (625): tre ipotesi ragionevoli sul perché
    `step_out` corresse fino all'uscita erano tutte sbagliate; una `eprintln!`
    temporanea ha dato la risposta in un colpo — `target = 0x0`. Le sonde vanno
    poi rimosse, come le perturbazioni.
17. **Un fix giusto può essere una regressione, e allora si restringe l'ambito**
    (625): il rifiuto dell'indirizzo nullo è corretto ovunque, ma su iOS avrebbe
    aggiunto un rosso. Spedito dove non rompe, dichiarato dove è rimandato, e
    consegnata la causa radice a chi può chiuderla. Ridurre l'ambito e dirlo non
    è lo stesso che ridurlo in silenzio.
18. **Un `main` rosso batte un difetto nuovo** (623): la priorità è la build, non
    il conteggio dei round.
17. **Verificare le PROPRIE dichiarazioni del round precedente**: difetti reali
    dodici volte, e una **assoluzione** (612), che vale uguale.
18. **Un ciclo che riprende il target va limitato dagli EVENTI** (585), e
    **chiedere al kernel invece di assumere** (589, 594).
19. **Non alzare il cricchetto di un altro per farlo tacere**: alzarlo è disfarlo.
20. **Eseguire TUTTO ciò che il ciclo chiede**: il 605 è emerso perché su Linux
    non stavo eseguendo la suite MCP, solo quella del debugger.
21. **Un agente fallito per errore di server non è un difetto assente**: va
    rilanciato, e finché non lo è va dichiarato aperto.
