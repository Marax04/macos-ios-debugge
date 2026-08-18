# rustre-debug — stato misurato

> **Regola.** Ogni 4 iterazioni questo file va riscritto DA ZERO. È un cruscotto,
> non un registro. Precedente riscrittura: 614. Questa: **618**, aggiornata al **620**.
>
> **Ogni numero è misurato.** «Non dimostrato» = nessuna macchina raggiungibile
> ha risposto: lacuna dichiarata, non dettaglio.
>
> Ogni misura è presa in un `git worktree` su HEAD con i **soli hunk miei**
> applicati sopra. L'albero condiviso contiene in permanenza lavoro non
> committato di altri attori e spesso non compila; misurarlo non è misurare.

---

## 1. Semaforo

| Dove | Verificato come | Esito |
|---|---|---|
| Windows x86_64 | suite locale, worktree isolato | **2060 / 0** |
| Linux x86_64 | WSL, `--test-threads=1` | **2043 / 0** |
| Darwin ×2 | `cargo check --target` | **0 errori** |
| MCP | Windows | **399 / 1** |
| Windows ARM64 | CI `windows-11-arm` | compila (602, 606); non riconfermato dopo il 612 |
| Linux aarch64 | CI `ubuntu-24.04-arm` | 3 fallimenti al 608; **i fix 607/608/609 non sono mai stati rimisurati** |
| macOS Intel / Apple Silicon | CI | suite e live test **verdi** |
| iOS Simulator | CI `macos-14`, arm64 reale | **verde** |
| iOS device | CI | compila e **linka** i test; non esegue (serve hardware) |

Le due suite del debugger sono **interamente verdi** dal 617, per la prima volta.
L'unico rosso è quello dell'MCP, e non è mio: **172 tool** rispondono senza i
parametri che il loro schema dichiara obbligatori contro un soffitto di 168, e di
quei 172 **zero** hanno prefisso `debug_`/`linux_`/`macos_`/`ios_`/`win_` — sono
`il_*`, `pe_editor_*`, `trace_*`, `symb_*`, `sandbox_*` di altri crate. Era 170 al
605 e 172 al 612: sale sotto altri attori. Va riportato al proprietario, **non**
fatto tacere alzando il soffitto.

## 2. Le tre famiglie di difetti che questo crate produce

1. **Un fallimento riportato come successo**: `let _ =`, `else { continue }`,
   `unwrap_or(0)` che trasforma «non ce l'ho» in zero, un `bool` in cui «non
   trovato» e «non riuscito» collassano, un `Drop` che tace, `dropped` lasciato
   vuoto per una scrittura mai partita.
2. **Logica condivisa che deriva**: fra i quattro backend, fra backend e MCP, fra
   una capacità DICHIARATA e il codice che la nega. Cinque round di fila hanno
   trovato questo: tre copie con tre risposte diverse (612, 614), due tabelle per
   una decisione (616), **quattro** elenchi dello stesso insieme di nomi (618).
3. **Un'assunzione sbagliata su CHI è la macchina**: x86 assunto dove gira ARM
   (byte di trappola, PAC, slot, trap flag), e — più sottile — l'architettura
   dell'**host** usata per interpretare i registri del **target** (615, 616).

## 3. Chiuso di recente, con la misura

- **Una capacità dichiarata assente ora viene RIFIUTATA con la sua stessa
  ragione** (620). `backend_capabilities()` pubblica, per piattaforma e per
  architettura, se una cosa funziona **e perché no** — e il commento su quella
  lista dice che una risposta sbagliata è peggio di nessuna. Nessuno la
  consultava. Su Windows-on-ARM la lista dice che i watchpoint hardware non ci
  sono e spiega che questo backend programma i registri di debug x86, che quella
  architettura non ha; `set_watchpoint_sized` non ne sapeva nulla, eseguiva
  l'intero ciclo di arming contro `dr0..dr7` inesistenti, trovava `armed == 0` e
  rispondeva **`NotAttached`** — una diagnosi che manda il chiamante a guardare
  la propria sessione, che non era il problema. Ora `capability_refusal` legge la
  ragione dalla stessa lista che la pubblica, così le due non possono divergere,
  e un guard strutturale impone a tutti e tre i backend di chiedere prima di
  armare. Verificato leggendo, non supponendo: Linux e macOS dichiarano
  `supported: true` senza condizioni, quindi lì il guard è un **no-op stretto** e
  i watchpoint ARM Linux del 570/608/609 non vengono toccati.
- **Un `dr7` assente non è più un thread disarmato** (619). I tre backend
  decidevano con `regs.get("dr7").unwrap_or(0)` e trattavano lo `0` come «nulla
  armato, salta questo thread» — mentre **tre righe sopra** gli stessi cicli
  gestiscono bene il caso vicino: un thread i cui registri non si riescono a
  LEGGERE finisce in `still_armed` col commento «UNVERIFIED, not clean». Un set
  letto che non CONTIENE `dr7` è la stessa situazione e riceveva la risposta
  opposta. Non è ipotetico su nessuno dei due fronti ARM64: il lettore AArch64
  di Windows **non pubblica affatto** `dr7` (AArch64 ha `Bcr`/`Bvr`/`Wcr`/`Wvr`),
  quindi lì ogni thread risultava pulito sempre; e su Linux ARM `dr7` è
  sintetizzato da `NT_ARM_HW_WATCH`, che `merge_debug_state` abbandona quando
  non riesce a leggerlo — cioè proprio il guasto che questo file ha aperto
  contro il runner ARM. Ora `debug_register_state` distingue
  `Clean`/`Armed`/`Unverifiable`. Dove si può riportare, l'assenza va in
  `still_armed`; nel percorso di `Drop`, dove non c'è nulla a cui rispondere,
  l'assenza fa **eseguire** il disarmo invece di saltarlo: scrivere zeri a un
  thread che non ne aveva costa una scrittura, saltarne uno che ne aveva lascia
  una trappola armata in un processo che stiamo abbandonando.
- **Condizioni sui breakpoint: cinque nomi di registro non erano offerti** (618).
  `SUB_REGISTER_NAMES` è ciò che i tre backend desktop iterano per popolare il
  contesto di valutazione. Mancavano `sil`, `dil`, `bpl`, `spl` ed `eip` — tutti
  risolvibili. Una condizione che ne nominava uno non valutava, e per la regola
  fail-open il target si fermava a **ogni** hit: la condizione non era sbagliata,
  non veniva applicata, e nulla lo diceva. Il guard che già esisteva controllava
  una sola direzione — che ogni nome pubblicizzato risolva — e una lista vuota lo
  avrebbe soddisfatto. Il nuovo guard sorveglia la direzione mancante, e ha
  subito colto il mio fix incompleto: un **quarto** elenco, lo schema in
  `register_context.rs`, non aveva i quattro byte bassi REX.
- **iOS: `fp` e `lr` non arrivavano mai al device** (617). `encode_into` piazzava
  `Pc` e `Sp` e non `Fp` né `Ra`. Poiché `decode` riempie i campi tipizzati a
  ogni lettura, un leggi-modifica-riscrivi ci portava l'edit del chiamante;
  `encode_into` ci riscriveva sopra il valore stantio e lasciava `dropped` vuoto,
  quindi `Ok(())` per una scrittura che il device non ha mai visto. Su arm64 sono
  frame pointer e indirizzo di ritorno: la coppia con cui si fa un backtrace.
- **Una sola tabella dei sotto-registri** (616). `register_view` e
  `sub_register_of` erano state scritte in parallelo da due attori. Un test
  differenziale ha chiesto loro di **concordare** invece di presumere quale fosse
  giusta: 5 divergenze reali, senza alcuna verità esterna.
- **`pc`/`sp`/`fp` seguono il TARGET, non il build** (615, 616), in entrambe le
  direzioni. `native_arch()` è l'host, scelto a compile time; su host x86_64 con
  device arm64 cercava `rip` dove il target pubblica `pc`.
- **Nomi di registro stretti in lettura e scrittura** (613, 614). `eax` non si
  leggeva affatto, `ax` restituiva 64 bit, e scrivere `eax` non faceva nulla.
- **Scritture a `fp`/`lr`/`x29`/`x30` non più scartate** (612): tre backend
  pubblicavano entrambe le grafie e ne preferivano una **diversa** ciascuno.
- **Breakpoint software su macOS** (579): non funzionavano affatto.
- **Watchpoint e breakpoint hardware su ARM64 Linux** (570, 571, 589, 594).
- **macOS riporta l'indirizzo di fault** (595).
- **Windows ha una CI** (597) e il backend **compila per ARM64** (602, 606).
- **Sei tool MCP Linux riparati** (605).

## 4. iOS — giri avversariali

| Giro | Agenti | Confermati | Chiusi |
|---|---|---|---|
| 6 | 77 | 9 | **9** |
| 7 | 68 | 12 | **12** |
| 8 | 74 | 15 | **2** |
| 8 (retry) | 64 | 5 | **5** |

Il giro 8 non è stato fermato dal codice: **13 agenti di fix sono morti su errori
server** (529 Overloaded, un 521, un 500). Il retry dalla cache ne ha recuperati
**5 su 5, zero errori**: fra questi, un `E0D` (EACCES da `task_for_pid`: SIP,
entitlement mancante, o un altro debugger già collegato) riportato come
`ProcessNotFound`, cioè un processo vivo e visibile in `ps` diagnosticato come
inesistente; e un id di thread a 64 bit troncato a `ThreadId(0)`, che è il
carattere jolly «lascia stare la selezione dello stub». I 2 chiusi sono reali: una maschera di
preservazione fissa a 64 bit che distruggeva i bit alti scrivendo `s3`/`h3`/`b3`,
e una sign-extension a 60 bit invece di 56 che rendeva `-(1<<40)` un positivo
enorme.

## 5. Difetti aperti — dichiarati

| Cosa | Dove | Stato |
|---|---|---|
| **iOS non onora `Breakpoint::condition`** | iOS | trovato al 618 e **non corretto**: `condition_allows_stop` compare 5 volte in ciascuno dei tre backend desktop e **0** volte in `apple_debugger.rs`, mentre il tipo documenta «only stop when this evaluates to true». Su iOS un breakpoint condizionale si ferma a ogni hit. Non toccato perché il giro 8 sta riscrivendo quel file |
| **13 difetti iOS confermati** | iOS | verificati da tre scettici, fix mai eseguito per errori API |
| **PAC nell'unwinder** | Linux ARM | 573 e 591 erano codice morto; il 607 lo legge per primo. **Mai rimisurato in CI** |
| **2 test sui registri di debug** | Linux ARM | `NT_ARM_HW_WATCH` sembra fallire su quel runner: da capire, non da indovinare |
| **Cricchetto MCP 172/168** | tutti | non mio, misurato al 612 e al 618 |
| **Single step su Windows ARM** | Windows | rifiutato esplicitamente (606): il meccanismo AArch64 non è implementato e inventarlo sarebbe peggio |
| **Watchpoint hw su Windows ARM** | Windows | il CONTEXT ha `Bcr`/`Bvr`/`Wcr`/`Wvr` (**2 slot**, non 4). Capacità dichiarata assente (598) e ora anche **rifiutata a runtime con quella ragione** (620) |
| **Eventi di thread** | macOS, iOS | Mach e RSP non li consegnano. Dichiarati assenti col motivo |
| **`task_for_pid` root** | macOS | ⚠️ **decisione dell'utente** |
| **iOS su hardware** | infrastruttura | i runner ospitati non hanno iPhone. Il simulatore però è arm64 REALE |
| **14 file `.bak*`** | `src/` | ⚠️ **decisione dell'utente** |

## 6. Lezioni di metodo

1. **Misurare il rosso PRIMA.** Se passa al primo colpo, **perturbare**. Un rosso
   da *compilazione* è il tipo debole: dimostra che manca una funzione, non che
   il comportamento fosse sbagliato.
2. **Il rosso misurato smentisce spesso quello previsto** (613): prevedevo «64
   bit», la misura diceva `None`. Si corregge la frase, non la misura.
3. **Due implementazioni della stessa decisione: farle CONCORDARE, non scegliere
   a occhio** (616, 618). Il test differenziale non assume che nessuna sia
   giusta. Nessuna verità esterna serve: se il codice si contraddice, un lato
   sbaglia.
4. **Un guard che sorveglia la PRESENZA non vede la COMPLETEZZA** (618): quello
   su `SUB_REGISTER_NAMES` verificava che ogni nome elencato risolva — una lista
   vuota lo soddisfa. Il gap stava nella direzione opposta.
5. **Un fix incompleto lo dice il guard giusto** (618): aggiunti i cinque nomi,
   un quarto elenco è diventato rosso all'istante.
6. **Un difetto risolto in una direzione va cercato nell'altra** (613→614,
   615→616): lettura/scrittura, mappa→tipizzato/tipizzato→mappa.
7. **Ancorare a un IDENTIFICATORE, mai a una stringa** che può stare in un
   commento. Costato quattro volte, incluso un guard soddisfatto dalla propria
   prosa.
8. **Un test può passare A VUOTO** dove i `cfg` lo compilano via, e **un file
   `cfg`-gated non è verificato dalla suite che non lo compila** (611).
9. **Un fix può essere giusto e MORTO**: sul thread sbagliato (573), dietro
   un'uscita anticipata (591), dentro un `cfg` mai compilato.
10. **Un rifiuto esplicito NON è un difetto** (606, 601) — **ma verificane la
    PREMESSA** (614): un guard rifiutava `eip` chiamandolo «un typo per `rip`»,
    e invece è la metà bassa di `rip`. Premessa falsa, rifiuto sbagliato.
    Distinguere i due casi è il giudizio che serve: nel 601 la difesa era
    stabilita per bisezione contro una rottura reale.
11. **Il difetto sta spesso nella FRASE**, non nel codice (612, 614, 617).
12. **Un mio fix può rendere FALSA la frase di un altro** (617): il 616 corresse
    `sync_map_from_special` e la doc di un guard iOS ne citava ancora il difetto
    come motivo della propria esistenza. Metà del motivo reggeva: corretta la
    metà falsa, non cancellata la frase.
13. **`native_arch()` risponde all'HOST** (615): dove una decisione dipende
    dall'architettura, chiedersi *di chi* è l'architettura rivela il difetto.
14. **Non copiare un FILE intero da un albero condiviso per misurare** (617):
    due volte ho importato lavoro non committato altrui insieme al mio, e
    entrambe le volte il rosso sembrava mio e non lo era. Si applica il proprio
    HUNK su HEAD.
15. **Attenzione all'INDICE dopo un commit da worktree** (617): l'albero
    principale conteneva un'inversione del mio stesso commit, pronta a essere
    committata dal prossimo attore.
16. **Attribuire con PROVA, nelle due direzioni**: un rosso va eseguito a HEAD
    senza le proprie modifiche prima di chiamarlo altrui — e prima di chiamarlo
    proprio.
17. **Verificare le PROPRIE dichiarazioni del round precedente**: difetti reali
    dieci volte, e una **assoluzione** (612), che vale uguale.
18. **Un ciclo che riprende il target va limitato dagli EVENTI** (585).
19. **Chiedere al kernel invece di assumere** (589, 594).
20. **Non alzare il cricchetto di un altro per farlo tacere**: alzarlo è disfarlo.
21. **Eseguire TUTTO ciò che il ciclo chiede**: il 605 è emerso perché su Linux
    non stavo eseguendo la suite MCP, solo quella del debugger.
22. **Una perturbazione va SEMPRE ripristinata** (giro 8, retry): un agente ha
    trovato una riga di produzione lasciata perturbata da un round precedente,
    con un marcatore `//PERTURB` ancora attaccato e il test che la copriva
    rosso. La tecnica che dimostra un rosso diventa il difetto se ci si ferma a
    metà. Verificato al 619: **zero** marcatori residui nel crate.
23. **Una capacità DICHIARATA va anche IMPOSTA** (620): la lista era accurata e
    dettagliata, e nessuna riga di codice la consultava. Fra dichiarare e
    imporre c'è la stessa distanza che fra un commento e un test. La ragione va
    LETTA dalla dichiarazione, non riscritta accanto: una seconda copia diverge.
24. **Verificare una propria dichiarazione trova difetti anche quando la
    dichiarazione è giusta** (620): il 598 diceva il vero, ma il percorso a
    runtime lo contraddiceva. Undicesima volta che questo controllo paga.
25. **Distinguere «non lo so» da «no» vale anche a tre righe di distanza** (619):
    lo stesso ciclo trattava «non ho potuto leggere» come non verificato e «non
    c'è» come pulito.
24. **Un agente fallito per errore di server non è un difetto assente**: va
    rilanciato, e finché non lo è va dichiarato aperto (giro 8).
