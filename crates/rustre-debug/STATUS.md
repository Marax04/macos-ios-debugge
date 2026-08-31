# rustre-debug — stato misurato

> **Regola.** Ogni 4 iterazioni questo file va riscritto DA ZERO. È un cruscotto,
> non un registro. Precedente riscrittura: 618. Questa: **624**, aggiornata al **627**, con due
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
| Windows x86_64 | suite locale, worktree isolato | **2097 / 0** |
| Linux x86_64 | WSL, `--test-threads=1` | **2080 / 0** |
| Darwin ×2 | `cargo check --target` | **0 errori** |
| MCP | Windows | **400 / 1** |
| Windows ARM64 | CI `windows-11-arm` | compila (602, 606); non riconfermato dopo il 612 |
| Linux aarch64 | CI `ubuntu-24.04-arm` | 3 fallimenti al 608; **i fix 607/608/609 non sono mai stati rimisurati** |
| macOS Intel / Apple Silicon | CI | suite e live test **verdi** |
| iOS Simulator | CI `macos-14`, arm64 reale | **verde** |
| iOS device | CI | compila e **linka** i test; non esegue (serve hardware) |

**Le due suite del debugger sono interamente verdi dal 626.** Resta solo l'**1**
dell'MCP: il cricchetto dei fabbricatori, noto e non mio (§4).

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
| ~~**iOS non onora `Breakpoint::condition`**~~ **RITIRATA AL 632 — ERA FALSA** | iOS | Vedi la sezione del 632. iOS non implementa condizioni, pass count né filtro di thread, e i tre **default del trait RIFIUTANO** con `Unsupported` nominando il motivo (`lib.rs:2761/2786/2811`). Non è un fallimento silenzioso: è un **terzo stato dichiarato**. Ora presidiato da `ios_refuses_breakpoint_restrictions_it_could_never_evaluate` |
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

- **Un argomento MCP presente ma illeggibile non diventa più il default** (627).
  `u64_arg_aliased` restituiva il default ogni volta che `coerce_u64` diceva
  `None`, e `None` copriva due situazioni diverse: «il chiamante non l'ha
  mandato» e «il chiamante ha mandato qualcosa che non so leggere». Una
  richiesta con `len: "sixteen"` veniva servita come se non avesse detto nulla —
  sedici byte di memoria, nessun errore, nessun indizio che l'argomento fosse
  stato scartato: il chiamante legge la risposta come risposta alla domanda che
  credeva di aver fatto. Ora l'assente resta default e il **presente-illeggibile**
  è un rifiuto che nomina la chiave.
  Il secondo pezzo è peggiore perché è silenzioso due volte:
  `debug.set_watchpoint` faceva `u64_arg_aliased(&args, "size", 8) as u8`, quindi
  `size: 256` e `size: 4096` arrivavano entrambi come **0** — un watchpoint che
  non sorveglia nulla, senza che nulla fra la richiesta e i registri di debug
  dicesse che il numero era cambiato. `u8_arg_checked` rifiuta invece di troncare.

- **⚠ CORREZIONE DI UNA MIA DIAGNOSI, e il rosso chiuso** (626). Al 625 avevo
  scritto che il mock «non serve via `m` le proprie scritture di stack». **Era
  falso.** Le letture `m` e l'interprete usano la stessa `self.memory`: gli zeri
  erano **veri**. Il programma sintetico su cui girano quei test saltava
  all'indirizzo sbagliato — `bl` prende un displacement **PC-RELATIVE**, e
  `bl(0x14)` a offset `0x08` arriva a `0x1C`, non al `0x14` che il commento
  accanto dichiara. L'esecuzione scavalcava del tutto il prologo del chiamato e
  `step_out` leggeva il frame di `main`, il cui `x30` salvato è genuinamente
  zero perché `main` non ha chiamante. Corretto il displacement: **tutti e 10**
  i test di `step_out` verdi, e la metà iOS del rifiuto rimandata al 625 è stata
  cablata. La lezione è che un numero misurato (`target = 0x0`) non porta con sé
  la propria spiegazione: la sonda aveva ragione, la mia frase no.

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
| 10 | 67 | 11 | **11** |

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
16. **Cercare bene e non trovare è un risultato** (627): cinque superfici dei
    backend desktop — `run_to_return`, la pulizia per-indirizzo di
    `remove_breakpoint`, le scritture parziali, `step_over`, i displacement dei
    programmi sintetici — sono state esaminate e sono risultate corrette. Nove
    round di irrobustimento si vedono. Il difetto è stato poi trovato nello
    strato che ne ha ricevuto molta meno, l'MCP: **dove non si è ancora guardato
    batte dove si è già guardato nove volte.**
17. **Una misura giusta non è una diagnosi giusta** (625→626): la sonda diceva
    il vero (`target = 0x0`) e la spiegazione che ci ho costruito sopra era
    falsa. Il numero va spiegato risalendo, non completato a intuito — e la
    frase sbagliata va corretta dove è stata scritta, non solo dove fa danno.
17. **Sondare batte dedurre** (625): tre ipotesi ragionevoli sul perché
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



---

## Iterazione 628 — 2026-08-19

### ⚠ REGOLA CORRETTA: questo file si AGGIUNGE, non si riscrive

L'utente ha ribadito che qui va scritto **tutto**, ogni round, e che **non si
cancella mai nulla**. Stavo violando la regola: alle iterazioni **614**, **618**
e **624** avevo riscritto il file **da zero**, seguendo la clausola del ciclo
«ogni 4 round riscrivilo da zero». Ogni riscrittura ha distrutto misure e cause
dei round precedenti. Dove le due istruzioni confliggono, **prevale quella
dell'utente**. Le tre versioni cancellate sono state recuperate da git
(`git show <riscrittura>^:path`) e riportate integralmente nell'ARCHIVIO in
coda: il file passa da 134 a **937 righe**. Da qui in avanti cresce soltanto.

### Difetto: un numero troppo largo per il suo campo veniva TRONCATO, non rifiutato

Otto siti in `rustre-mcp-tools/src/tools/debug.rs` restringevano un argomento
del chiamante con un `as` nudo, che **wrappa**:

| Sito | Effetto |
|---|---|
| `req_u64(&args, "pid")? as u32` ×2 | `pid: 4294967297` → **pid 1**: il debugger si attacca a un **processo diverso**, vivo, scelto in silenzio |
| `.ok_or_else(…"local_pid requires 'pid'")? as u32` | idem |
| `.ok_or_else(…"process requires 'pid'")? as u32` | idem |
| `…"gdb_server requires 'port'"))? as u16` | `port: 65536` → **porta 0** |
| `…"remote requires 'port'"))? as u16` | idem |
| `opt_u64(&args, "tid", 1) as u32` | un tid oltre `u32::MAX` → **`ThreadId(0)`**, che il giro 9 ha stabilito essere il **carattere jolly** RSP «qualunque thread lo stub avesse selezionato» |
| `opt_u64(&args, "word_size", 8) as u8` | `256` → **0** |

Nessuno di questi è un rifiuto che il chiamante possa vedere: ognuno è **una
domanda diversa, risposta come se fosse quella fatta**. `narrowed_arg` ora
rifiuta nominando argomento, valore e ciò su cui avrebbe agito.

**Rosso misurato** (testo esatto):
`a tool still narrows a caller-supplied number with a bare 'as', which wraps: "pid")? as u32`

### Due difetti DENTRO il mio stesso guard, corretti

1. **Il guard pescava i propri letterali.** `include_str!` include anche il
   modulo di test, quindi la lista di forme vietate faceva scattare il guard su
   sé stessa. Gli aghi sono ora **costruiti a runtime**, mai scritti interi.
2. **Poi pescava la propria prosa.** Restavano due occorrenze della forma
   incriminata nei **doc comment** che la descrivono — la trappola «un guard
   soddisfatto dalla propria prosa», vista dal lato che *fallisce*. Ora i
   commenti vengono rimossi prima della scansione. Ho attribuito la prima
   occorrenza al test e mi sbagliavo: erano commenti.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2116 / 0** |
| Linux (WSL, `--test-threads=1`) | **2099 / 0** |
| Darwin ×2 (`cargo check --target`) | **0 errori** |
| MCP | **401 / 1** — il +1 è questo test, l'1 è il cricchetto dei fabbricatori |

I conteggi sono saliti (2097→2116, 2080→2099) perché `main` ha assorbito 214
commit di altri attori con i loro test.

### Giro 11 iOS: 56 agenti, 9 confermati, 9 chiusi

Fra gli esiti: uno **SIGSEGV con `reason:signal` classificato come Breakpoint** —
il crash spariva dal report e un hit veniva accreditato a una BRK mai eseguita;
e un processo nuovo che **ereditava la tabella dei breakpoint** del precedente
quando il detach non era riuscito a disarmarli.

### Trappole di misura riportate dagli agenti — da tenere

- **`git diff` sull'albero condiviso NON è «il mio hunk».** Fra due catture lo
  stesso file è passato da 105 a 465 inserzioni; importando quel diff un agente
  si è attribuito **2 rossi altrui**. La cattura affidabile è ricostruire la
  patch a mano sopra `main`.
- **Un worktree cancellato da un altro attore a metà build** ha prodotto
  `couldn't read build.rs (os error 3)` **ed exit 0** dal pipe: un **finto verde**
  per chi non legge l'output.
- **`CARGO_TARGET_DIR` condiviso** fra agenti: 16 minuti di attesa sul file lock,
  scambiati per un blocco.
- **La sandbox scarta in silenzio le scritture fuori dal progetto**: un worktree
  è risultato vuoto senza alcun errore.


---

## Iterazione 629 — 2026-08-19

### Difetto: gli accessori OPZIONALI davano lo stesso valore ad «assente» e «illeggibile»

Il 627 aveva tolto questa forma da `u64_arg_aliased`, che aveva **2** call site.
Restava in piedi in `opt_u64` e `opt_str` — cioè negli accessori che i tool
**usano davvero**, con **11 e 6** siti.

```rust
fn opt_u64(args, key, default) { args.get(key).and_then(coerce_u64).unwrap_or(default) }
fn opt_str(args, key, default) { args.get(key).and_then(Value::as_str).unwrap_or(default) }
```

- `tid: "main"` diventava in silenzio il thread **1**, e il tool riportava su un
  thread che il chiamante non aveva mai nominato.
- Il peggiore è `match opt_str(&args, "kind", "write")`: chi manda `kind: 5` si
  ritrova un watchpoint di **SCRITTURA**, in silenzio, quando magari stava
  armando una lettura — e il tool risponde successo.

`req_u64` era invece **già corretto**: verificato, non supposto.

**Rosso misurato:** `a tool still reads an optional argument through the
unchecked accessor, so a value it cannot read becomes the default in silence:
opt_u64(&args`

**17 siti cablati** su `opt_u64_checked` / `opt_str_checked` — sei `opt_str` e non
quattro come avevo contato a occhio: il conteggio meccanico ha corretto il mio.

### Regressione CAUSATA DA ME, e come si è chiusa

La rinomina ha fatto diventare rosso
`tests_extra::a_declared_timeout_is_a_timeout_that_is_read`, un guard di
**rustre-debug** che scandisce il sorgente **MCP** con `include_str!` su un
percorso relativo fra crate. Provato che era mio e non preesistente: su `main`
pulito passa.

Il guard era ancorato al **nome dell'accessore** (`opt_u64(&args, "timeout_ms"`),
quindi rinominare l'accessore lo ha rotto senza che il suo soggetto cambiasse.
È la **quarta** volta nella sessione che un'asserzione ancorata a una stringa
significa altro da ciò che intendeva — e il commento sopra di essa ne contava
già tre.

Ri-ancorato all'**intento**, non alla grafia: in una chiamata il nome è seguito
da `,` e da un default, in una dichiarazione di schema da `:`. Quella
distinzione sopravvive a qualunque rinomina. Il guard **non è stato indebolito**:
la versione controllata soddisfa il suo intento meglio di prima, perché rifiuta
anche un valore malformato.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2116 / 0** |
| Linux (WSL, `--test-threads=1`) | **2099 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **402 / 1** — il +1 è questo test, l'1 è il cricchetto |

### Giro 12 iOS: 42 agenti, 7 confermati, 7 chiusi

Complementare al mio: un agente ha trovato il **gemello lato stub** del difetto
del 628. Il mio era un argomento del **chiamante** che *wrappava*
(`4294967297 → 1`); il suo è il pid riportato dallo **stub** via `qProcessInfo`
che veniva **saturato a 0** con `unwrap_or(0)` — un pid presente reso
indistinguibile da «nessun processo». Due facce della stessa classe, su due
sorgenti di dato diverse.

Altri esiti: un `Drop` che riscriveva la memoria del target **senza rilasciare il
resume parcheggiato**, quindi il pacchetto andava a un processo ancora in
esecuzione, la stop reply dovuta non arrivava mai e ogni `BRK #0` auto-piantata
restava in un target vivo; e un `NSNumber` tagged con nibble 6 (double) che
fabbricava un denormale invece di rifiutare — 60 bit di payload, 56 dopo lo
shift, segno ed esponente strutturalmente a zero.

### Trappola di misura riportata da un agente

Una prima misura era stata **troncata da `tail -8`** e mostrava solo «could not
compile … 1 previous error», senza il testo dell'errore: la riesecuzione con log
completo ha rivelato che il difetto era **in un altro file**. Un output tagliato
è una misura che mente per omissione.


---

## Iterazione 630 — 2026-08-30

### Audit sistematico: la classe dei guard ancorati a stringa è PULITA

Il problema dell'ancoraggio era emerso **quattro volte** in questa sessione, così
l'ho spazzato meccanicamente invece di aspettare la quinta.

| Controllo | Esito |
|---|---|
| Ancore `item_body` che non esistono più nel sorgente scandito | **0 su 57** |
| Asserzioni positive che passano SOLO grazie a un commento | **0 su 28** |
| `include_str!` in `lib.rs` | 294, di cui ~39 filtrati da `code_only` |

E `item_body` è già ben difeso: va in **panic** se l'ancora manca, e **rifiuta**
un corpo implausibilmente grande — con un commento che spiega perché
(«il corpo sarebbe tutto ciò che segue l'ancora, e conterrebbe ogni ago che un
guard potrebbe cercare»). Qualcuno ci aveva già pensato, e bene.

**La prima versione della mia spazzata aveva lo stesso difetto che cercava**:
appaiava ogni ancora con ogni file incluso dal modulo, senza sapere quale fosse
davvero scandito, e produceva 17 falsi positivi. Rifatta con l'ambito per
**funzione di test**, il numero è sceso a zero. Un risultato negativo vale solo
quanto lo strumento che l'ha prodotto.

### Difetto: un float che un `u64` non può contenere veniva SATURATO

`coerce_u64` accettava qualunque float non negativo con `fract() == 0.0` e poi
faceva `f as u64`, che in Rust **satura**. `1e30` non ha parte frazionaria,
quindi passava il controllo e usciva come **`u64::MAX`**.

I chiamanti usano questa funzione per `addr`: una richiesta di leggere memoria a
`1e30` diventava una richiesta di leggere a **`0xFFFFFFFFFFFFFFFF`**, in
silenzio, e la risposta parlava di un indirizzo che nessuno aveva chiesto.

**Rosso misurato:** `left: Some(18446744073709551615)  right: None`

Il confine è tracciato a **2^53**, dove un `f64` smette di rappresentare interi
consecutivi: sopra quella soglia il numero che arriva non è il numero che è
stato mandato, saturazione o no. Un float che non si può tenere esatto viene
rifiutato, e gli accessori controllati del 627/629 trasformano quel rifiuto in
un errore leggibile invece che in un default.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2116 / 0** |
| Linux (WSL, `--test-threads=1`) | **2099 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **403 / 1** — il +1 è questo test, l'1 è il cricchetto |


---

## Iterazione 631 — 2026-08-30

### Difetto: una lettura CORTA non diceva di esserlo, mentre la gemella lo fa

`debug.write_memory` riporta `"success": bytes_written == data.len()`, quindi
una scrittura parziale è visibile nella risposta. La sua gemella
`debug.read_memory`, **nello stesso file, poche righe più su**, riportava solo
`"len": bytes.len()` — la lunghezza **arrivata**, sotto una chiave che si legge
come la lunghezza **chiesta**, e senza il `len` della richiesta da nessuna parte.

`read_memory` può legittimamente restituire meno byte: un bordo di pagina, una
regione parzialmente mappata, un target morto a metà chiamata. Chi ne chiedeva
64 e ne riceveva 8 vedeva `len: 8` e una stringa esadecimale corta, e non gli
veniva detto nulla: per accorgersene doveva ricordare la propria richiesta e fare
il confronto — cioè esattamente il confronto che lo strumento di scrittura fa
già per lui.

Due strumenti adiacenti in un solo file, in disaccordo su se valga la pena
nominare un risultato parziale: la famiglia 2 sopra la famiglia 1. Ora
`read_memory` pubblica `requested_len` e `complete`.

Il guard è ancorato **anche** sul comportamento del gemello
(`bytes_written == data.len()`), così se qualcuno togliesse la completezza dal
lato scrittura questo test se ne accorgerebbe invece di restare verde su una
premessa svanita.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2116 / 0** |
| Linux (WSL, `--test-threads=1`) | **2099 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **404 / 1** — il +1 è questo test, l'1 è il cricchetto |

### Giro 13 iOS: 37 agenti, 5 confermati, 5 chiusi

- `DW_FORM_addrx` non veniva mai risolto: l'**indice** finiva nel campo
  indirizzo, e `low_pc` usciva come `Some(0)` — indistinguibile da un'unità
  davvero basata a zero. La sezione `__debug_addr` veniva raccolta e **mai
  letta**. Ora un indice non risolvibile lascia `None`: terzo stato.
- Uno stop su watchpoint pubblicava un breakpoint **fabbricato** invece del
  record tracciato: l'evento diceva `hit_count 0` mentre `breakpoints()` diceva
  2 — lo stesso debugger dava due numeri per lo stesso watchpoint. E una chiave
  `watch:` senza record veniva riportata come «armata e autentica».
- Un watchpoint elencato non pubblicava la **larghezza** con cui era stato
  armato, quindi chi lo riarmava dall'elenco ripiegava su un default.

### Perturbazione altrui, trovata e verificata chiusa

Un agente ha segnalato una **perturbazione ancora attiva** in produzione lasciata
da un altro: `lldb_ext.rs:866`, `is_accessible()` ridotta a `self.is_mapped()`
con marcatore `PERTURBAZIONE_TEMPORANEA_RIPRISTINARE`. Ha fatto la cosa giusta —
l'ha **segnalata senza toccarla**, essendo lavoro non committato altrui.
Verificato al 631: **sparita dall'albero condiviso e mai entrata in `main`**.
È la seconda volta che questa classe emerge e la seconda volta che si chiude da
sé; resta il motivo per cui la regola «ripristina sempre» è scritta due volte.


---

## Iterazione 632 — 2026-08-30

### ⚠ UNA MIA AFFERMAZIONE FALSA, portata avanti per quattro giri

STATUS.md dichiarava dal **618**: «iOS non onora `Breakpoint::condition`;
`condition_allows_stop` compare 5 volte nei tre backend desktop e 0 in
`apple_debugger.rs`, quindi su iOS un breakpoint condizionale si ferma a ogni
hit». **Era falsa**, e l'ho ripetuta nel prompt di ogni giro iOS dal 11 al 14 —
quattro giri con una lente puntata su un difetto che non esiste.

Un agente del giro 14 l'ha smontata, e l'ho **verificata di persona** prima di
accettarla: i tre default del trait (`set_breakpoint_condition`,
`set_breakpoint_thread_filter`, `set_breakpoint_ignore_count`, a `lib.rs:2761 /
2786 / 2811`) rispondono `Unsupported` **nominando il motivo** — «one attached
here would never be evaluated». iOS non li implementa, quindi eredita il
rifiuto. Non c'è nessun fallimento silenzioso: **la difesa funziona**, ed è
esattamente il «terzo stato» che questo file predica.

Il mio errore di ragionamento: ho contato le occorrenze di
`condition_allows_stop` e dedotto l'assenza della *capacità* dall'assenza di
quel *nome*.

Peggio: le tre guardie sorgente di `lib.rs` iterano solo su
windows/linux/macos, quindi **nessun test copriva il comportamento iOS su quelle
tre API** — la mia affermazione falsa non era falsificabile da nulla. L'agente ha
aggiunto la guardia runtime mancante, asserendo sul **valore** (`Err(Unsupported)`
con la ragione) e non sull'esistenza del metodo: scatta se un domani un setter
cominciasse a rispondere `Ok(())` senza un gate nel percorso di stop. Per
misurare il rosso ha **perturbato la produzione al comportamento che STATUS.md
affermava**, e poi ha ripristinato.

Non ha potuto correggere STATUS.md — fuori dal suo perimetro — e ha lasciato il
testo corretto. L'ho usato.

### Difetto: un `dr7` illeggibile pubblicato come `0`, ed è di UN THREAD

`live_debug_registers` è la sorgente del `dr7` che ogni strumento sui watchpoint
riporta, e conteneva **entrambe le metà del difetto del 619**, nello strato che
il 619 non aveva raggiunto:

- `regs.get("dr7").unwrap_or(0)`, e un intero `(0, [0; 4])` quando
  `get_registers` fallisce. Zero in `DR7` significa «nessuno slot abilitato»,
  quindi un set di registri illeggibile — e un'architettura che il `DR7` non ce
  l'ha affatto, come il lettore AArch64 di Windows — venivano entrambi pubblicati
  come «nulla è armato». Chi controllava che un watchpoint fosse davvero rimosso
  leggeva `dr7: 0` ed era soddisfatto.
- Legge `self.tid` **soltanto**. Su x86 i registri di debug sono **per thread**:
  il backend arma e disarma ogni thread, ed è il motivo per cui tiene una lista
  `still_armed`. Il `DR7` di un thread, sotto una chiave `dr7` nuda, descrive il
  processo solo quando il processo ha un thread solo.

Ora la funzione restituisce `Option`, riusa `debug_register_state` del 619 —
così i due strati non possono divergere — e i quattro siti pubblicano
`dr7: null` quando non è conoscibile, più `dr7_thread` accanto al valore.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2116 / 0** |
| Linux (WSL, `--test-threads=1`) | **2099 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **405 / 1** — il +1 è questo test, l'1 è il cricchetto |

### Superfici esaminate e trovate CORRETTE

- La validazione di `size` sui watchpoint: il backend rifiuta larghezze diverse
  da 1/2/4/8 **e** gli indirizzi non allineati, con messaggi espliciti.
- `remove_watchpoint`: disarma l'hardware **prima** e libera l'id solo dopo, col
  commento che spiega perché l'ordine inverso sembra equivalente e non lo è.

### Giro 14 iOS: 39 agenti, 4 confermati, 4 chiusi

- Un `metype`/`medata` con prefisso `0x` **collassava a un segnale nudo**:
  `Exception{metype:1,...}` diventava `Signal(11)`. Due lettori della stessa
  coppia chiave/valore si contraddicevano; ora puntano alla stessa funzione.
- Un breakpoint all'**ingresso** di una funzione frameless faceva scalare `sp` di
  0x20 per locali **mai allocate**.


---

## Iterazione 633 — 2026-08-30

### Difetto: le guardie cross-backend coprono TRE backend, e ce ne sono quattro

Il 632 aveva mostrato che la mia affermazione falsa su iOS era sopravvissuta
perché **nessun test la poteva contraddire**. Questo round misura quanto è esteso
quel buco, invece di aspettare la prossima affermazione non falsificabile.

| Misura | Valore |
|---|---|
| Siti che iterano su ≥2 backend | **85** |
| Che nominano iOS | **1** |
| Che lo omettono | **84** |

E `COVERED` — la lista che dichiara quali backend sono coperti — **nomina**
`apple_debugger.rs`, con un messaggio che promette: «Every guard that encodes a
cross-backend invariant must name it». Misurato, quella promessa è mantenuta da
**un sito su 85**. Ancora una volta una capacità **dichiarata** e non **imposta**.

**La maggior parte di quelle omissioni è giusta.** iOS è un backend RSP remoto:
non ha un byte `int3` da piantare, non ha `DR7` da programmare, non ha `ptrace`,
non ha `CONTEXT`. Una guardia sui registri di debug x86 non ha motivo di
nominarlo, e aggiungerlo a tutte e 84 sarebbe **inventare copertura**, non
ottenerla.

Ma «per lo più giusto» non è «misurato», e il buco è già costato: il 618 ha
registrato, e questo file ha ripetuto per quattro giri, che iOS ignora in
silenzio le condizioni sui breakpoint. Non è vero — i default del trait
rifiutano con una ragione. L'affermazione è sopravvissuta perché le tre guardie
su quelle API iterano sui tre desktop. **Un backend non testato non è un backend
che funziona: è un backend su cui nessuno può essere smentito.**

Quindi il numero è **fissato**, non le omissioni chiuse. Un nuovo invariante
cross-backend che salti iOS fa fallire il guard, e chi lo aggiunge deve
decidere consapevolmente — che è tutto ciò che mancava. La frase falsa in
`COVERED` è stata ristretta a ciò che quel guard davvero controlla.

### Due strumenti, due numeri: 80 contro 84

Il conteggio ad hoc scritto per esplorare diceva **80**; la scansione Rust che
resta nel test dice **84**. Il primo cercava array di tuple con una regex, il
secondo conta qualunque blocco fra parentesi quadre con due o più
`include_str!` — più grezzo, e ne prende quattro in più. **Il numero fissato è
quello dello strumento che continuerà a girare**: l'altro era impalcatura. Che i
due divergano è esattamente il motivo per cui la cifra deve venire da lì.

### Terza volta: un guard che pesca il proprio letterale

L'asserzione sulla frase falsa cercava quella frase in `include_str!("lib.rs")`
— che include anche il test, quindi trovava sé stessa e non poteva mai diventare
verde. Già successo al 628 e al 629; l'ago va **costruito** a runtime, mai
scritto per intero. Terza volta in sei iterazioni.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2117 / 0** |
| Linux (WSL, `--test-threads=1`) | **2100 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **405 / 1** — l'1 è il cricchetto dei fabbricatori |


---

## Iterazione 634 — 2026-08-30

### Difetto: 11 guardie MCP potevano essere soddisfatte — o battute — dal proprio testo

Tre volte in sei iterazioni (628, 629, 633) un guard ha pescato il **proprio**
letterale, perché `include_str!("debug.rs")` include anche il modulo di test in
cui il guard vive. Ogni volta l'avevo aggirato **localmente**, costruendo l'ago a
runtime o filtrando i commenti. Tre aggiramenti per **un helper mancante**.

Il crate gemello ha `production_sources()` dal **553**, col commento che spiega
la parte non ovvia: il taglio va fatto al **modulo** di test, non al **primo**
`#[cfg(test)]`, perché quell'attributo marca anche singoli helper centinaia di
righe più in su — e tagliare lì una volta nascose un backend vero a una guardia
che doveva trovarlo. Nell'MCP quell'helper **non esisteva**.

`production_only` ora c'è, e le guardie ci passano. Con il taglio, un ago non
può più essere trovato dal test che lo cerca.

**Rosso misurato sul valore:** `11 guard(s) scan this file WITHOUT the cut`.

### Quattro tagli prematuri, trovati mentre convertivo

Convertendo è emerso che **quattro** guardie tagliavano già al primo
`#[cfg(test)]` — esattamente l'errore contro cui il commento del crate gemello
mette in guardia. Non è un dettaglio di stile: quel taglio nascondeva codice di
**produzione** alla guardia che doveva ispezionarlo. Sostituiti con l'helper.

### Un'asserzione VACUA, mia, corretta prima di spedire

La prima stesura contava gli `include_str!` **nel codice di produzione** — dove
per costruzione non ce n'è nessuno, perché ogni guardia vive nel modulo di test
che il taglio rimuove. Passava misurando **niente**. Riscritta per contare il
lato test, dove le scansioni stanno davvero: da lì il rosso vero, 11.

E l'eccezione legittima è **nominata**, non allentata: una sola scansione grezza
resta, quella di questo test, che per misurare le altre deve vedere il file
intero. Un `raw >= wrapped` sarebbe passato per qualunque numero di guardie non
protette — ed è la forma di asserzione che questo file continua a trovare nei
test altrui.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2117 / 0** |
| Linux (WSL, `--test-threads=1`) | **2100 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **406 / 1** — il +1 è questo test, l'1 è il cricchetto |

### Giri 15 e 16 iOS: 66 agenti, 8 confermati, 8 chiusi

- Un `launch` la cui risposta alla `A` andava in **timeout** lasciava l'inferiore
  creato e fermo al suo entry point **senza inviare vKill/k/D**, e da lì
  `kill()`/`detach()` rispondevano `NotAttached` perché la sessione era `None`.
  Il filo osservato finiva letteralmente in `$A26,0,...` e basta.
- `memory_maps()` rispondeva **`Ok` con zero regioni** quando lo stub non
  implementa `qMemoryRegionInfo`: una mappa vuota indistinguibile da un processo
  senza memoria. Ora è `Unsupported`, come già faceva `modules()`.
- Un nome di regione con byte **non UTF-8** collassava a `None`: «chiave
  assente», «payload non esadecimale» e «byte non decodificabili» erano lo stesso
  valore. E il decoder vecchio usava `filter_map`, che su una cifra non valida
  avrebbe **accorciato** i byte in silenzio.
- Un `pc` **presente sul filo** diventava un'assenza, perché `from_snapshot`
  risolveva per ruolo generico invece che col `role_or_name` che tutto il resto
  del backend usa.


---

## Iterazione 635 — 2026-08-30

### ⚠ LIMITE DI SPESA MENSILE RAGGIUNTO — la metà iOS è ferma

Il giro 16 ha riportato **4 confermati e 0 chiusi**: tutti gli agenti di fix sono
morti su «You've hit your monthly spend limit». Non è un errore transitorio come
i 529 del giro 8 — è un limite dell'account, e **solo l'utente può rimuoverlo**
(claude.ai/settings/usage). Finché resta, lanciare altri `/workflows` produce
solo fallimenti. Il lavoro Windows/Linux/MCP continua normalmente.

### Difetto: un backtrace troncato era indistinguibile da uno completo

Tutti e tre i backend desktop camminano `for _ in 0..32` — il numero **scritto
dentro il ciclo** — e restituiscono un `Vec<StackFrame>` nudo. Chi riceve 32
frame non può sapere se lo stack ne aveva 32 o se la camminata è stata
abbandonata al tetto. E nemmeno lo strumento MCP che li inoltra: `debug.backtrace`
pubblicava `frames` e nient'altro.

Per un debugger è la forma peggiore disponibile: **un backtrace incompleto
presentato come completo**, sulla risposta che si legge per prima quando qualcosa
è andato storto, e proprio nel caso — ricorsione profonda — in cui un backtrace
serve davvero. È lo stesso difetto della lettura corta del 631, sulla superficie
più visibile del debugger.

`BACKTRACE_FRAME_CAP` è ora **pubblicata**, i tre backend la usano al posto del
letterale, e l'MCP riporta `frame_cap` e `truncated`.

### Il cricchetto del 633 mi ha fermato, ed è servito

Aggiungendo la guardia sul tetto — che itera sui tre desktop e **omette iOS** — il
conteggio dei siti cross-backend è passato da 84 a 85 e **il cricchetto del 633 ha
fatto fallire la suite**. Ha funzionato esattamente come progettato: impedire che
un invariante cross-backend salti iOS *senza una decisione*. Applicato al suo
autore, due round dopo.

La decisione, presa e scritta: iOS **non** usa `BACKTRACE_FRAME_CAP` — il suo
unwinder ha un `max_depth` proprio e configurabile, quindi l'invariante «cammina
il tetto pubblicato» non lo descrive. Ma **il difetto esiste anche lì**, con una
costante diversa: `AppleUnwinder::backtrace` si ferma a `max_depth` e restituisce
i frame senza dire se è stato troncato. **Dichiarato aperto**, non risolto per
assimilazione.

### Due superfici esaminate e trovate PULITE

- Le 8 guardie di `rustre-debug` che scandiscono `lib.rs` (sé stesse): un solo
  ago esiste unicamente nel modulo di test, ed è quello del **mio** guard del
  633, che per contare guardie che vivono nei test deve legittimamente vedere il
  file intero. Nessun difetto reale: la classe chiusa nell'MCP al 634 qui non ha
  gemelli. La trappola era peraltro già nota **dal 449**, con la contromisura
  scritta caso per caso.

### Un'ancora assunta invece che verificata

Ho inserito la costante ancorandomi a una riga di doc che **ricordavo**, non che
avevo letto: il testo reale era diverso e lo script si è fermato sull'assert. Due
tentativi persi. L'assert ha fatto il suo lavoro — ma la lezione è che l'ancora
va **letta** prima di usarla, non ricostruita a memoria.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2118 / 0** |
| Linux (WSL, `--test-threads=1`) | **2101 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **406 / 1** — l'1 è il cricchetto dei fabbricatori |


---

## Iterazione 636 — 2026-08-30

### Difetto INTRODOTTO DA ME al 635, trovato e chiuso

Il 635 ha pubblicato `BACKTRACE_FRAME_CAP` e ha fatto riportare all'MCP
`truncated: frames.len() >= BACKTRACE_FRAME_CAP`. È giusto per i tre backend
desktop, che camminano **32** — ed è **sbagliato per iOS**, il cui unwinder ha
`max_depth: 128`. Su una sessione iOS uno stack genuino di trentadue frame veniva
quindi dichiarato **troncato**: un falso allarme proprio sulla cosa che quel
campo esiste per riportare onestamente.

Mio, del round precedente, e della stessa famiglia del **615**: la costante di un
backend presa per quella di tutti. E la cura è la stessa — **chiedere a chi lo
sa**. `Debugger::backtrace_frame_cap()` ha un default (il valore desktop) e iOS
lo sovrascrive con la profondità che il suo unwinder cammina davvero, ora
pubblicata da `AppleUnwinder::max_depth()`. L'MCP chiede al backend invece di
assumere.

Questo chiude anche la metà iOS che il 635 aveva **dichiarato aperta**: il
difetto del backtrace troncato-e-taciuto non esiste più su nessuno dei quattro
backend.

**Rosso misurato:** `the MCP compares every backend's frame count against the
DESKTOP cap, so an iOS stack of 32 frames is reported truncated when its real
limit is 128`.

### Un guard altrui mi ha fermato, e aveva ragione

`every_source_claim_names_a_call_this_path_really_makes` verifica che una
dichiarazione `"source"` nella risposta nomini una chiamata fatta **entro 60
righe**. Il mio commento dentro l'oggetto di risposta aveva allontanato le due
cose oltre quella finestra.

Non l'ho allentato: la spiegazione che avevo messo lì **duplicava** quella già
scritta nella doc di `backtrace_frame_cap`, dove è il posto giusto per leggerla.
Tolta da dove ripeteva, il guard è tornato verde da solo. Un guard sulla
prossimità è una misura grezza, ma qui ha indicato una prosa fuori posto — che è
esattamente il tipo di cosa per cui vale la pena averlo.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2119 / 0** |
| Linux (WSL, `--test-threads=1`) | **2102 / 0** |
| Darwin ×2 | **0 errori** — l'aarch64 compila l'override iOS |
| MCP | **406 / 1** — l'1 è il cricchetto dei fabbricatori |

### Nessun giro iOS lanciato

Il limite di spesa mensile è ancora attivo (§635): lanciare `/workflows` produce
solo agenti che muoiono. Ripartiranno quando l'utente lo rimuove. Il lato
positivo, per questa iterazione: `src/ios/` non era conteso da nessuno, e questo
ha reso sicuro toccarlo — cosa che dal giro 11 in poi avevo evitato.


---

## Iterazione 637 — 2026-08-30

### Difetto: uno stop `reason:signal` senza numero diventava il segnale ZERO

`ThreadStopReason::from_parts` si contraddiceva **dentro sé stessa**. Il ramo del
segnale leggeva `Self::Signal(signo.unwrap_or(0))`, quindi uno stop reply che
diceva `reason:signal` con un `signo` mancante o non parsabile veniva consegnato
come **`Signal(0)`**.

Il segnale 0 non è un segnale: in POSIX è la sonda «questo processo esiste?», e
`kill(pid, 0)` non recapita nulla. Il chiamante riceveva quindi «fermato da un
segnale che non può essere recapitato», e un crash il cui numero non si era
letto veniva riportato così.

**La prova stava due rami più sotto, nella stessa funzione**: il ramo di riserva
scrive `(None, Some(s)) if s != 0 => Self::Signal(s)` — cioè rifiuta lo zero come
segnale, correttamente. Una contraddizione interna, che come al 616 non ha
bisogno di alcuna verità esterna per essere dimostrata.

E anche la forma della risposta onesta era già lì: il ramo `exception` risponde
`Other("exception")` quando il suo dettaglio manca. Ora il ramo `signal` fa lo
stesso, e i due rami concordano sullo zero.

**Rosso misurato:** `left: Signal(0)  right: Other("signal")`.

### Due superfici esaminate e trovate CORRETTE

- **Chunking delle letture RSP**: `read_memory` rispetta il `PacketSize`
  negoziato, e c'è già il test
  `a_read_larger_than_the_packet_size_is_split_into_several_m_packets`.
- Lo scan della famiglia «assenza spacciata per valore» in `src/ios/` ha trovato
  **49 occorrenze in produzione**; questa è la prima chiusa e le altre restano
  da vagliare una a una — la maggior parte sono legittime (un contatore che parte
  da zero non è un'assenza).

### Nota sull'ambiente, chiesta dall'utente

Le suite Linux girano **davvero su WSL sul PC dell'utente**: kernel
`6.18.33.2-microsoft-standard-WSL2`, Ubuntu 24.04.4 LTS, host `DESKTOP-DOHAOMH`,
cargo 1.96.0. La riga «La virtualizzazione annidata non è supportata in questo
computer» che `wsl.exe` stampa a ogni invocazione è un **avviso**, non un errore.

La prova che sia una compilazione genuinamente diversa e non Windows travestito:
i conteggi divergono (2103 contro 2120) e `linux_debugger.rs` è
`#[cfg(target_os = "linux")]` — su Windows **non viene compilato affatto**. È la
lezione costata dall'iterazione 611: per un file `cfg`-gated, solo la piattaforma
che lo compila lo verifica.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2120 / 0** |
| Linux (WSL2 sul PC dell'utente, `--test-threads=1`) | **2103 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **406 / 1** — l'1 è il cricchetto dei fabbricatori |

### Nessun giro iOS: limite di spesa ancora attivo (§635)


---

## Iterazione 638 — 2026-08-30

### Difetto: un frame senza frame pointer veniva pubblicato come `Some(0)`

`UnwindFrame::to_stack_frame` riempiva **incondizionatamente**
`fp: Some(Address::new(self.regs.fp))`. Ma `crate::StackFrame::fp` è un
`Option<Address>`, e quell'`Option` esiste **apposta** per dire «non lo so».

Quindi ogni frame il cui `x29` non era mai stato letto — e ogni frame alla fine
genuina della catena, dove per convenzione il frame pointer è nullo — veniva
consegnato al chiamante come un frame **il cui frame pointer È l'indirizzo zero**.
L'indirizzo zero non è un frame pointer.

**La prova era nello stesso file, milletrecento righe più sotto**:
`validated_frame_record_step` rifiuta `regs.fp == 0` con
`ImplausibleFrame("frame pointer is null")`. Una metà del file tratta lo zero
come **impossibile**, l'altra metà lo consegnava come **valore**. Contraddizione
interna, come al 616 e al 637: non serve alcuna verità esterna per dimostrarla.

E la doc **due righe sopra** la riga incriminata dice testualmente
*«Symbolication is left to a `FrameSymbolResolver`; this crate never invents
names.»* Non inventava nomi, e inventava un frame pointer.

**Rosso misurato:** `left: Some(Address(0))  right: None`.

Il test sorveglia anche il contrario, perché la cura non deve dilagare: un frame
pointer reale (`0x7100`) deve sopravvivere intatto, e `pc`/`sp` — che **non**
sono opzionali — restano riportati come sono.

### Tre candidati esaminati e trovati NON difetti

Continuando il vaglio delle 49 occorrenze «assenza spacciata per valore» in
`src/ios/` (aperto al 637, questa è la seconda chiusa):

- **`lldb_ext.rs:105`** — `u8::from_str_radix(rest, 16).unwrap_or(0)`:
  **irraggiungibile**, protetto a monte da
  `rest.len() <= 2 && rest.bytes().all(|b| b.is_ascii_hexdigit())`.
- **`rsp.rs:1325`** — `self.incoming.pop_front().unwrap_or(0)`:
  **irraggiungibile**, `n = cap.min(self.incoming.len())` limita il ciclo; ed è
  per giunta codice del mock, non di produzione.
- **`unwind.rs:222`** (l'`fp` dentro `From<&RegisterSet>`) — qui `unwrap_or(0)`
  **è onesto**: `validated_frame_record_step` risponde con un rifiuto esplicito
  e nominato, non con un falso «fine catena». Il difetto non era lì: era a
  valle, dove lo zero veniva **pubblicato**.

Questa distinzione è il punto del giro: uno stesso `unwrap_or(0)` è innocuo
finché resta interno a un calcolo che rifiuta lo zero, e diventa un difetto nel
momento in cui quel valore **esce verso il chiamante** dentro un `Option` che
avrebbe potuto dire la verità.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2121 / 0** |
| Linux (WSL2 sul PC dell'utente, `--test-threads=1`) | **2104 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **406 / 1** — l'1 è il cricchetto dei fabbricatori, non mio |

**Il cricchetto si è mosso: 172 → 175 su 2390 tool.** Non è mio e non è il mio
fix: una modifica in `rustre-debug` non può aggiungere tool all'MCP. Verificato
come nei giri precedenti — **zero** dei 175 è un tool `debug.*` (l'unica
corrispondenza in output è il nome file `debug.rs` nel percorso d'errore). La
salita è lavoro di altri attori sul crate MCP. Resta la regola: **non si chiude
alzando il tetto**.

### Nessun giro iOS: limite di spesa mensile ancora attivo (§635)

Resta in vigore. Ogni agente di fix del workflow muore su «You've hit your
monthly spend limit»; solo l'utente può rimuoverlo da claude.ai/settings/usage.


---

## Iterazione 639 — 2026-08-30

### Difetto: `debug.backtrace` non pubblicava affatto il frame pointer

Il backend calcola `StackFrame::fp`, e **tutti e due** i renderer di
`debug.backtrace` lo scartavano. Un chiamante leggeva `addr` e `sp` ma il frame
pointer non gli arrivava mai — sulla risposta che si guarda per prima quando
qualcosa è andato storto.

L'omissione si nascondeva dietro le fixture, che portano un **misto voluto** di
`Some` e `None`: il dato era costruito correttamente e poi buttato via.

**Rosso misurato:**
`{"frame":0,"addr":5368713216,"sp":5637040384,"name":"main","module":"target.exe","offset":0}`
— nessuna chiave `fp`, mentre il frame 0 della fixture ne ha uno noto.

Il campo è **nullable**, e non è un dettaglio: `null` qui è una risposta vera.
L'unwinder lo produce per un frame il cui `x29` non è mai stato letto e per il
terminatore nullo che chiude una catena (§638). Serializzarlo come 0
ricollasserebbe esattamente la distinzione che il backend tiene.

### È questo che rende visibile il §638

Da solo, il fix del 638 restava confinato dentro il crate: correggeva la
coerenza interna ma **non cambiava nulla di ciò che l'utente vede**, perché il
campo non usciva. Vale la pena dirlo così: una correzione che nessuno può
osservare non è ancora un guadagno per chi usa lo strumento.

### Due tentativi miei mi hanno corretto prima di arrivarci

1. **Ancoraggio sbagliato**: ho inserito il test sopra `async fn`, che però è
   preceduta dal proprio `#[tokio::test]` — la mia funzione si è presa due
   attributi e quella vicina è rimasta senza. Il compilatore l'ha fermato.
2. **Rosso VACUO**: il primo test falliva su `missing required field
   'session_id'`, cioè **prima** dell'asserzione che mi interessava. Un rosso
   che fallisce per il motivo sbagliato non prova niente.

Dal secondo è uscito un rilievo per un giro futuro: **`debug.session_open`
restituisce `session_id` come NUMERO, `debug.backtrace` lo pretende come
STRINGA** (`req_str`). Chi incatena i due tool nel modo ovvio riceve «missing
required field», messaggio fuorviante: il campo c'era, aveva solo il tipo che
l'altro tool produce.

### Il guard di prossimità mi ha fermato per la SECONDA volta

`every_source_claim_names_a_call_this_path_really_makes` (§636) è scattato di
nuovo: il mio commento di nove righe dentro l'oggetto JSON aveva spinto la
dichiarazione `"source"` oltre le 60 righe dalla chiamata che nomina. Come al
636 **non l'ho allentato**: la spiegazione lunga sta nel doc comment del test,
nel corpo bastano due righe.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2121 / 0** |
| Linux (WSL2 sul PC dell'utente, `--test-threads=1`) | **2104 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **407 / 1** — passati 406 → 407 (il test nuovo); l'1 è il cricchetto |

Il cricchetto resta a **175 su soffitto 168**, non mio, zero tool `debug.*`.

### Nessun giro iOS: limite di spesa mensile ancora attivo (§635)


---

## Iterazione 640 — 2026-08-30

### Difetto: un PID non rappresentabile diventava ZERO — che qui significa già «nessun processo»

`establish` e il ri-attacco dopo `launch` narrowavano il pid con
`u32::try_from(info.pid).unwrap_or(0)`. Ma **lo zero non è un valore libero in
questo backend**: `detach` e `kill` lo scrivono entrambi
(`self.pid.store(0, Ordering::SeqCst)`) per dire «nessun processo», e
`target_pid()` è gatato **solo** sul flag `attached`.

Conseguenza: su un attacco **riuscito**, un pid che non entra in 32 bit veniva
restituito al chiamante come `Some(ProcessId(0))` — attaccato, al kernel. Due
significati sulla stessa costante, e vince quello sbagliato proprio quando lo
stub dice qualcosa di inatteso.

`ProcessInfo::pid` è un `u64` perché il campo della reply è letto come esadecimale
di larghezza non limitata. Un pid che il crate non sa rappresentare è un pid che
non sa indirizzare: ora l'attacco **fallisce** invece di procedere su uno inventato.

### Il rosso, misurato in DUE passi per non barare

Un test che chiama una funzione inesistente non è un rosso, è un errore di
compilazione. Quindi ho prima estratto `narrow_pid` **conservando il
comportamento vecchio**, e il test ha mostrato il valore realmente prodotto:

```
a pid beyond 32 bits must be refused: zero already means `no process` here: ProcessId(0)
```

Poi l'ho fatta rifiutare. Il verde arriva dopo aver visto lo sbaglio, non al
posto di averlo visto.

### Due punti, non uno

`establish` e il ri-attacco condividevano il difetto e ora passano **entrambi**
da `narrow_pid`: una correzione su uno solo sarebbe rimasta verde mentendo
sull'altro (cfr. [[feedback_contare_i_punti]]).

Il test sorveglia anche il verso opposto: un pid 0 **realmente riportato** dallo
stub deve passare, perché è un'affermazione diversa dal fallimento della
conversione. Il sentinella è un input legittimo; a essere illegittimo era
fabbricarlo.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2122 / 0** |
| Linux (WSL2 sul PC dell'utente, `--test-threads=1`) | **2105 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **407 / 1** — l'1 è il cricchetto dei fabbricatori |

### Nessun giro iOS: limite di spesa mensile ancora attivo (§635)


---

## Iterazione 641 — 2026-08-30

### Difetto: il ri-armamento leggeva un `dr7` ASSENTE come un `dr7` pulito

`rearm_watchpoints_on_new_threads` esiste **identica nei tre backend desktop**, e
tutte e tre leggevano `regs.get("dr7").unwrap_or(0)`.

L'assenza non è zero. **Verificato alla fonte, non preso dal commento**: il
lettore AArch64 di Windows (`context_to_register_set`) pubblica **zero** registri
`dr*` — contati — e quello Linux li omette quando `NT_ARM_HW_WATCH` non è
leggibile.

Conseguenza: un **successo silenzioso**, la forma che questo crate condanna
ovunque. `dr7` letto come 0 fa sembrare liberi tutti gli slot, l'armamento
procede, e la scrittura è controllata **solo** per l'errore di `set_registers` —
mai riletta — quindi l'indirizzo non finisce in `unarmed` e il chiamante viene
informato che è sorvegliato mentre nulla lo sorveglia.

### La cura era già nel file, ottanta righe più sopra

`debug_register_state` (lib.rs:1191) classifica in Clean / Armed / **Unverifiable**,
e la doc di quest'ultimo dice testualmente che da lì non si può concludere nulla —
«and in particular not that the thread is clean». Il ramo onesto esisteva pure:
un thread i cui registri non si riescono a **leggere** già estende `unarmed`.
Ora il ramo `Unverifiable` fa la stessa identica cosa.

### Tre punti, non uno

Tre backend, tre siti. La guardia li conta insieme e **asserisce di averli
raggiunti tutti e tre** (`checked == BACKENDS.len()`), perché una guardia che
esamina meno di quanto dichiara è verde per il motivo sbagliato.

**Rosso misurato:** `linux_debugger.rs: the re-arm path must classify the set,
not assume it`.

### Un percorso ESCLUSO deliberatamente

`set_watchpoint_sized` legge `dr7` **dopo** aver scritto e conta uno slot come
armato solo se ha attecchito: lì l'assenza fallisce in chiusura, non in apertura,
quindi è onesta per costruzione e non va toccata. Distinguere i due casi è il
punto del giro: lo stesso `unwrap_or(0)` è innocuo dove esiste una verifica a
valle e diventa un difetto dove la decisione è finale.

### Nota di metodo

La guardia vive in `tests_extra` ma `production_sources` sta in `tests_expanded`:
moduli fratelli non vedono gli item privati l'uno dell'altro. Risolto con
`pub(super)` sull'helper di test — nessuna modifica alla produzione.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2123 / 0** |
| Linux (WSL2 sul PC dell'utente, `--test-threads=1`) | **2106 / 0** — il fronte che conta, `linux_debugger.rs` è `cfg`-gated |
| Darwin ×2 | **0 errori** |
| MCP | **407 / 1** — l'1 è il cricchetto dei fabbricatori |

### Nessun giro iOS: limite di spesa mensile ancora attivo (§635)


---

## Iterazione 642 — 2026-08-30

Il giro era stato interrotto dallo spegnimento con tre fronti su quattro verdi;
la suite MCP, lasciata in background, ha poi risposto **407 / 1** e il giro si
chiude completo. (La riga «IN ALBERO, NON COMMITTATA» che stava qui è superata:
tenuta a verbale perché lo stato intermedio è esistito davvero.)

### Difetto: il DISARMO leggeva un `dr7` assente come «nessun registro armato»

Gemello del §641, negli stessi tre backend e con conseguenza **opposta**.
`disarm_watchpoint_registers` leggeva `regs.get("dr7").unwrap_or(0)`: su un
insieme privo di `dr7` ogni slot risulta disabilitato, nessuno corrisponde
all'indirizzo, e la funzione risponde `Ok(false)` — «nessun debug register lo
teneva». È un'affermazione **sull'hardware** ricavata da un insieme che
l'hardware non l'ha mai descritto.

Il file lo sapeva già **quattro righe più sopra**: quando i registri non si
riescono a LEGGERE solleva un errore che dice testualmente «it is not known
whether a debug register still holds {addr}». L'assenza riceve ora la stessa
risposta.

`Ok(false)` resta una risposta legittima e il test lo sorveglia: un thread che
davvero non ha slot su quell'indirizzo non è un errore. A non dover
sopravvivere era **produrla per ignoranza**.

**Rosso misurato:** `linux_debugger.rs: the disarm path must classify the set,
not assume it`.

### La guardia mi ha corretto due volte, ed entrambe a ragione

1. Errore di sintassi mio: `let ... else` con or-pattern richiede le parentesi.
2. Dopo il rifiuto avevo lasciato la **rilettura ridondante**
   `regs.get("dr7").unwrap_or(0)`, e la guardia ha continuato a segnalare tutti
   e tre i file. **Non l'ho allentata**: ora il valore viene preso dalla
   classificazione stessa — che è anche la forma già usata nel §641, così i due
   percorsi si somigliano invece di divergere.

### Misure (parziali)

| Dove | Esito |
|---|---|
| Windows | **2124 / 0** |
| Linux (WSL2 sul PC dell'utente, `--test-threads=1`) | **2107 / 0** |
| Darwin ×2 | **0 errori** |
| MCP | **407 / 1** — l'1 è il cricchetto dei fabbricatori, non mio |

### Nessun giro iOS: limite di spesa mensile ancora attivo (§635)


---

## Iterazione 643 — 2026-08-31

### ⚠ Direttiva cambiata: iOS/macOS SOSPESO, solo Windows e Linux

Per ordine dell'utente. Dei due target Darwin resta la sola **verifica di
compilazione**, non lo sviluppo. Il lavoro Linux è ora parallelizzato via
`/workflows`; Windows lo conduco direttamente.

### Nota d'ambiente: il riavvio ha cancellato worktree e target dir

`wt638` e la sua `CARGO_TARGET_DIR` erano in `%TEMP%` e sono spariti col
riavvio. **Nulla è andato perso**, perché ogni giro finisce con commit e push:
`main` era intatto a `5d42762f3`. Ricreato `wt643` sullo stesso commit.
È la conferma pratica del perché si committa a ogni giro invece che a fine
sessione.

### Difetto: un campo di TIPO SBAGLIATO veniva riportato come MANCANTE

`req_str` e `req_u64` (`rustre-mcp-tools/src/lib.rs`) rispondevano
`missing required field '{key}'` in **due situazioni diverse**: campo assente, e
campo presente con il tipo sbagliato. Per il secondo caso il messaggio non è
scomodo, è **falso** — il chiamante il campo l'aveva mandato, e sentirselo dire
mancante lo manda a cercare un argomento che ha già passato.

**Non è ipotetico.** `debug.session_open` restituisce un `session_id` NUMERICO
mentre ogni altro tool del debugger lo legge come STRINGA (misurato: **50** punti
di chiamata `req_str`, **39** schemi che lo dichiarano stringa, **3** che lo
dichiarano numerico). Sono **due sistemi di sessione distinti** che condividono
il nome del campo — non un'incoerenza, come avevo scritto ieri, ma due famiglie
ciascuna coerente con sé stessa. Il difetto vero è che incatenarli produceva
«campo mancante» su un campo appena fornito.

**Rosso misurato:**
`the field was supplied — calling it missing is false. Got: missing required field 'session_id'`

La cura distingue i due stati, che è la stessa forma dei cinque giri precedenti:
l'assenza conserva il suo messaggio, il tipo sbagliato ottiene
`field 'x' must be a string, but a number was supplied` — e nomina anche **cosa**
è stato mandato. Il test sorveglia **entrambi i versi**: chi dimentica davvero un
campo deve continuare a sentirsi dire che manca.

### La popolazione, misurata: 24 occorrenze in 13 file

Lo stesso helper di quattro righe è **duplicato in tutto il crate**. Questo giro
chiude la coppia canonica in `lib.rs`, che serve i 50 punti di chiamata di
`debug.rs`. Le altre 22 occorrenze in 12 file restano aperte e vanno chiuse
facendole convergere su un helper solo, non ricopiando la cura 12 volte.

### Misure

| Dove | Esito |
|---|---|
| Windows | **2124 / 0** |
| Linux (WSL2 sul PC dell'utente, `--test-threads=1`) | **2107 / 0** |
| Darwin ×2 | **0 errori** (sola compilazione) |
| MCP | **408 / 1** — passati 407 → 408 (il test nuovo); l'1 è il cricchetto, invariato a 175 |


---

## Iterazione 644 — 2026-08-31 — copertura LIVE via workflow, e DUE errori miei corretti

### ⚠ RETTIFICA di una misura che avevo pubblicato: i test live di Windows

Nella panoramica data all'utente avevo scritto **«8 test live su Windows, 6 su
Linux»**. **È FALSO.** Avevo contato le occorrenze della *stringa* `live_tests`
nel file, non i test dentro il modulo.

I numeri veri, misurati:

| | Windows | Linux (prima del workflow) |
|---|---|---|
| Test nel modulo `live_tests` | **80** | **41** |
| Di cui lanciano o si attaccano a un processo vero | **77** | **42** |

Conseguenza: la diagnosi «il divario più grande è la copertura live» era
**sbagliata nella forma in cui l'ho detta**. Windows era gia' il piu' coperto
dei due. Resta vero che Linux era indietro, ed e' quello che il workflow ha
chiuso. Famiglia: [[feedback_contraddizione_smaschera_sonda]] — un conteggio
che non torna con l'ordine di grandezza atteso e' la sonda, non l'oggetto.

### ⚠ PUNTO CIECO DEL PROTOCOLLO: `--lib` non vede i test di integrazione

La direttiva dice `cargo test --release -p rustre-debug --lib` e l'ho sempre
eseguito alla lettera. Eseguendo per la prima volta `--tests`, e' emerso che
**`tests/apple_end_to_end.rs` fallisce 2 su 4 sotto Linux**, da PRIMA di questa
sessione, e nessuna delle mie misure lo vedeva:

- `full_debug_cycle_over_rsp` — `left: None  right: Some("caller")` (riga 218)
- `stepping_traverses_the_call_the_same_way_a_ui_would` (riga 281)

Il run si fermava li' e non arrivava nemmeno ai file live nuovi. E' esattamente
[[feedback_verde_non_significa_verificato]]: un controllo che gira, riporta un
esito, e non guarda l'oggetto. **Da ora la misura Linux include `--tests`.**
(Sono test del percorso Apple/RSP: la correzione ricade sotto la sospensione
iOS decisa dall'utente, quindi va a verbale come rosso NOTO, non chiuso.)

### Workflow #1 Linux — 5 agenti su 5, zero errori, 63 test live nuovi

Cinque file nuovi in `tests/`: `live_linux_breakpoints.rs` (21),
`live_linux_watchpoints.rs` (12), `live_linux_stepping.rs` (8),
`live_linux_regs_mem.rs` (14), `live_linux_threads_modules.rs` (9).

Non sono test in memoria: compilano al volo una fixture C, risolvono i simboli
con `nm`, lanciano sotto `ptrace`, e le asserzioni sui watchpoint leggono
**DR0-DR7 ripresi dal tracee**, non lo stato interno del debugger.

**DIFETTO 1 — `set_breakpoint_ignore_count(addr, 0)` cancella il filtro sul
thread.** `src/linux_debugger.rs:3503-3505`: il ramo `count == 0` rimuove
`ignore_counts` **e** `thread_filters`. «Ignora zero volte» significa «fermati a
ogni passaggio» e non dice nulla su quale thread. Rosso: atteso
`only_thread == Some(ThreadId(13380))`, ottenuto `None` — e `breakpoints()`
concorda con la perdita, quindi non c'e' modo di accorgersene.

**DIFETTO 2 — un watchpoint non raggiunge i thread creati DOPO l'armamento.**
Causa misurata, non dedotta: il clone *viene* osservato (`ThreadCreate` arriva),
ma su un tid nuovo `get_registers` risponde ESRCH perche' il backend non fa
`PTRACE_ATTACH` sui thread nati dopo il launch. `rearm_watchpoints_on_new_threads`
prende il ramo «registri illeggibili» — quello reso onesto al §641 — e riporta
l'indirizzo come non armato; **ma il chiamante era gia' stato informato che
l'indirizzo e' sorvegliato**. Miss silenzioso. Cura: `PTRACE_SEIZE` +
`PTRACE_O_TRACECLONE`.

**Un agente ha corretto SE STESSO, e va registrato**: due suoi test fallivano su
`read_memory`; invece di dichiarare un difetto ha capito che il TEST era
sbagliato — `read_memory` maschera di proposito i trap piantati, come gdb e
lldb — e ha aggiunto un test che fissa quel comportamento come voluto invece di
lasciarlo folklore.

### Workflow #2 Linux e #3 Windows lanciati subito dopo

Per regola dell'utente: appena un workflow chiude, si verifica e se ne rilancia
un altro. Vedi [[feedback_workflow_a_catena]].
- **#2 Linux** (`wu4e64nin`): ciclo di vita, segnali/ragioni di arresto, simboli
  e righe DWARF, espressioni e condizioni, mappe e moduli con `dlopen`.
- **#3 Windows** (`wcdru9aax`): ciclo di vita, eccezioni vere (access violation,
  divisione per zero, stack overflow), moduli e simboli con `LoadLibrary`,
  memoria e mappe, thread creati dopo l'attach.

### Misure di questo giro

| Dove | Esito |
|---|---|
| Windows `--lib` | **2124 / 0** |
| Linux `--lib` | **2107 / 0** |
| Linux `--tests` | **ROSSO NOTO**: `apple_end_to_end` 2/4 (preesistente, percorso Apple) |
| MCP | **408 / 1** |


---

## NOTA DI PROCEDURA — 2026-08-31: il file dell'utente era rimasto indietro di 11 giri

**Difetto MIO, di procedura, non di codice.** L'utente apre lo STATUS.md
nell'albero condiviso `Desktop/RustRE`. Io lavoro in un worktree separato
(`wt643`), committo da li' e faccio avanzare `main` con `git update-ref`. Quel
comando sposta il **puntatore del ramo** ma **NON aggiorna i file su disco**
nell'albero dell'utente.

Risultato misurato: il suo file era fermo a **1364 righe, ultima voce iterazione
633**; il mio ne aveva **2086, fino alla 644**. Undici giri di verbale non sono
mai arrivati al file che lui legge — mentre erano regolarmente in `main` e su
`origin`. Il registro esiste per essere letto: se non arriva dove viene letto,
non esiste.

**Regola nuova, da applicare a OGNI giro**: dopo il commit e l'`update-ref`,
copiare `STATUS.md` dal worktree all'albero condiviso.

Conservata a verbale la sola riga che differiva, una riga di cruscotto poi
aggiornata in luogo (la regola «aggiungi, non togliere» vale anche per quelle):

    | MCP | Windows | **405 / 1** (632) |


---

## Iterazione 645 — 2026-08-31

### Difetto: azzerare l'IGNORE COUNT cancellava anche il FILTRO SUL THREAD

`set_breakpoint_ignore_count(addr, 0)` significa «fermati a ogni passaggio». Non
dice nulla su QUALE thread: quello lo imposta una chiamata diversa,
`set_breakpoint_thread_filter`. Eppure il ramo `count == 0` rimuoveva anche
`thread_filters`, quindi una restrizione `break … thread N` spariva come effetto
collaterale di una chiamata che parlava d'altro — e `breakpoints()` **concordava
con la perdita**, lasciando il chiamante senza modo di accorgersi che il suo
breakpoint era diventato globale.

**Rosso misurato**, test LIVE contro un `cmd.exe` vero lanciato sotto il
debugger: `left: None  right: Some(ThreadId(65120))`.

### Tre punti, e la prova che era una copia

Il difetto era **identico** in `windows_debugger.rs:2820`,
`linux_debugger.rs:3503` e `macos_debugger.rs` — stessa forma e **stessa
indentazione sbagliata**, che è la firma del copia-incolla. Corretti insieme:
uno solo sarebbe rimasto verde mentendo sugli altri due.

Trovato dagli agenti sul backend Linux (§644), chiuso da me partendo da Windows
su richiesta dell'utente.

### Due rossi VACUI miei, prima di quello buono

1. Campo inesistente: `threads()` restituisce `ThreadId`, non strutture con `.id`.
2. `modules()` risponde `MemoryError(0, "CreateToolhelp32Snapshot failed: 299")`
   — ERROR_PARTIAL_COPY — mentre il loader sta ancora costruendo la lista. Il
   test falliva **prima** dell'asserzione che mi interessava.

Cura: prendere l'indirizzo dal **PC del thread fermo** (`get_registers(tid).pc`),
che è mappato ed eseguibile e non dipende dall'enumerazione dei moduli. Un rosso
che scatta sul punto sbagliato non prova nulla: cfr.
[[feedback_provare_il_ramo_che_scatta]].

### Misure

| Dove | Esito |
|---|---|
| Windows `--lib` | **2125 / 0** |
| Linux `--lib` | **2107 / 0** |
| Linux test LIVE | **61 / 0** (+3 `#[ignore]` che documentano difetti aperti) |
| Darwin x2 | **0 errori** (sola compilazione) |
| MCP | **408 / 1** — l'1 e' il cricchetto |

### Difetti Linux ancora APERTI, trovati al §644

1. Watchpoint che non raggiunge i thread nati dopo l'armamento (serve
   `PTRACE_SEIZE` + `PTRACE_O_TRACECLONE`).
2. `apple_end_to_end` 2/4 rosso sotto Linux — percorso Apple, sotto sospensione
   iOS, registrato come rosso NOTO.


---

## Iterazione 646 — 2026-08-31

### Difetto: una feature DOCUMENTATA che non poteva essere accesa in alcun modo

`nl_query.rs` gatava tre blocchi su `#[cfg(feature = "nl-query-llm")]`, e la doc
del modulo (`lib.rs:275`) diceva al lettore che quella feature «routes unmatched
questions to the Anthropic API».

Ma `crates/rustre-debug/Cargo.toml` **non aveva alcuna sezione `[features]`**.
Il gate non poteva essere vero per nessuna via: quel codice era **irraggiungibile
per sempre** mentre i documenti lo davano per disponibile. E non sarebbe nemmeno
compilato se qualcuno ci avesse provato, perche' usa `reqwest::blocking` e la
dipendenza del workspace non porta quella feature.

E' la famiglia «assenza spacciata per risposta» nella sua forma di manifest: il
manifest risponde «non esiste», la doc risponde «esiste», e il compilatore da'
retta al primo.

### Cablato, non zittito (regola dell'utente sui warning)

`[features] nl-query-llm = ["dep:reqwest"]` piu' `reqwest` opzionale con
`features = ["blocking"]`. **E verificato che ora si ACCENDA davvero**:
`cargo check --release -p rustre-debug --features nl-query-llm` → `Finished`,
zero errori. Dichiarare una feature che non compila sarebbe stato solo spostare
la bugia.

### La guardia e' generale, e mi ha corretto subito

`every_feature_gate_names_a_feature_the_manifest_declares` legge `Cargo.toml` con
`include_str!` e controlla ogni gate delle sorgenti di produzione.

**Prima versione: 3 bersagli, di cui 2 FALSI POSITIVI MIEI.**
- `watchpoint_engine.rs: avx2` — e' `target_feature`, una feature del PROCESSORE,
  che col manifest non c'entra nulla.
- `lib.rs: '...'` — un frammento di prosa dentro un commento.

Corretta: solo righe che iniziano con `#[cfg(`/`#[cfg_attr(`, ed esclusione
esplicita di `target_feature`. Aggiunta l'asserzione `inspected > 0`, cosi' la
guardia non puo' diventare verde perche' non guarda niente — cfr.
[[feedback_guardie_che_si_rompono_da_sole]].

Dopo la correzione resta **un solo bersaglio vero**, ed e' quello chiuso.

### I 73 warning, classificati

| classe | quanti |
|---|---|
| `usage of an unsafe block` (manca il commento SAFETY) | **69** |
| `unexpected cfg condition value: nl-query-llm` | **3** ← chiusa qui |
| `unused import: Seek` (`windbg_ttd_backend.rs:38`) | 1 |

I 69 non sono rumore: in un debugger che chiama Win32 e ptrace grezzi, ogni
blocco `unsafe` senza una motivazione scritta e' una promessa non verificata.
Fronte aperto.

### Misure

| Dove | Esito |
|---|---|
| Windows `--lib` | **2126 / 0** |
| Linux `--lib` | **2108 / 0** |
| Darwin x2 | **0 errori** (sola compilazione) |
| `--features nl-query-llm` | **compila** |


---

## WORKFLOW LINUX #2 — 2026-08-31 — 5 agenti su 5, zero errori, 46 test live

Aree: ciclo di vita, segnali/ragioni di arresto, simboli, espressioni, mappe e
moduli. Cinque file nuovi in `crates/rustre-debug/tests/`.

### ⚠ TRE STUB nei provider di simboli — capacita' DICHIARATE e ASSENTI

Non sono difetti di comportamento: sono funzioni che esistono, sono chiamabili,
e non fanno nulla. E' la classe piu' grave trovata finora.

1. **`ElfSymbolProvider::parse_elf` e' uno STUB che scarta OGNI simbolo.**
   Test `parse_elf_should_load_the_symbols_a_real_elf_contains`, `#[ignore]`.
2. **`DwarfSymbolProvider::load` e' uno STUB che restituisce un provider vuoto.**
   Test `dwarf_provider_load_should_read_debug_info_from_the_binary`, `#[ignore]`.
3. **Il parser del programma di riga RIFIUTA DWARF 5** — che e' il default dei
   compilatori attuali. Test `dwarf5_line_program_should_not_parse_to_zero_rows`,
   `#[ignore]`.

Il terzo workflow (`w12efkit6`) ha due agenti dedicati a misurare il divario
ESATTO: quanti simboli dovrebbero uscire da ogni forma di ELF (PIE, no-PIE,
strippato, con e senza `-g`) confrontando con `nm`, e quante righe escono da
`-gdwarf-4` contro `-gdwarf-5`.

### DIFETTO — `current_thread()` sopravvive alla fine della sessione

`kill()` e `detach()` azzerano pid, cmd_tx, breakpoints, hit_counts, disabled,
conditions, pending, ignore_counts, thread_filters, hw_watchpoints — ma **non
`current_tid`**. L'unico percorso che lo pulisce e' `retire_session_after_exit()`,
cioe' la sola uscita naturale del tracee.

Risultato: l'istanza si CONTRADDICE. `is_attached()` risponde gia' `false` mentre
`current_thread()` restituisce il tid del processo morto — e quel tid e' il
default su cui poggiano le chiamate di registri e stepping.

Rosso misurato: `current_thread answered ThreadId(15126) for a process killed
moments ago; the session is over and the only honest answer is NotAttached`.

**Misurato da me: il difetto e' nei TRE backend** (linux/windows/macos), in
nessuno dei quali `kill`/`detach` tocca `current_tid`. Tre punti.

### Un agente ha chiuso con ZERO difetti del backend, ed e' un buon segno

L'agente sui segnali: 8 test verdi, nessun difetto. I suoi 5 rossi iniziali erano
errori del TEST, non del codice, e li ha lasciati scritti nei doc comment perche'
sono trappole vere:
- un tracee appena lanciato e' fermo al trap di `exec` e non ha ancora eseguito
  nulla di `main`: un segnale inviato subito arriva PRIMA che il programma
  installi il gestore, e uccide per azione predefinita;
- il backend fa `waitpid(-1)`, quindi in un binario di test unico il figlio
  lasciato da un test precedente viene consegnato al debugger del test
  successivo — i test ora filtrano su `ev.pid`.

### Esiti dichiarati dagli agenti (da verificare dal coordinatore)

| file | esito |
|---|---|
| `live_linux_lifecycle.rs` | 13 ok, 1 ignore |
| `live_linux_signals.rs` | 8 ok |
| `live_linux_symbols.rs` | 6 ok, 3 ignore (i tre stub) |
| `live_linux_expressions.rs` | 9 test |
| `live_linux_maps_modules.rs` | 6 test |

### WORKFLOW LINUX #3 lanciato subito dopo (`w12efkit6`)

Aree: divario esatto di `parse_elf`, divario DWARF 4 contro DWARF 5, heap,
casi limite di lettura/scrittura memoria, casi limite dello stepping.


---

## Iterazione 647 — 2026-08-31

### Difetto: `current_thread()` sopravviveva alla fine della sessione

`kill()` e `detach()` azzeravano tutto — pid, canale dei comandi, tabelle dei
breakpoint, contabilita' dei watchpoint — **tranne `current_tid`**. L'unico
percorso che lo puliva era `retire_session_after_exit()`, cioe' la sola uscita
naturale del tracee.

Risultato: l'istanza si **contraddiceva**. `is_attached()` rispondeva gia'
`false` mentre `current_thread()` continuava a servire il tid del processo morto.
E quel tid non e' inerte: e' il thread predefinito su cui ricadono le chiamate di
registri e stepping, quindi chi si fidava operava su un thread inesistente.

**Rosso misurato** (test live, `cmd.exe` vero lanciato e poi ucciso):
`the session is over and the only honest answer is NotAttached, got: Ok(ThreadId(62284))`

### La cura e' un'INVARIANTE, non tre toppe

«Il thread corrente non puo' sopravvivere al pid.» Applicata **ovunque il pid
viene azzerato**: 3 punti per backend x 3 backend = **9 punti**. Il difetto era
in tutti e tre — misurato, non supposto: in nessuno `kill`/`detach` toccava
`current_tid`.

### Un altro rosso VACUO mio, e la causa vale la pena saperla

Il primo tentativo falliva con `a live session has a current thread: NotAttached`
**prima** dell'asserzione utile: `current_tid` non lo imposta il `launch`, lo
fissa il primo evento di arresto CONSUMATO. Cura del test: fare un
`continue_execution()` prima di misurare. Terzo rosso vacuo in tre giri — la
lezione [[feedback_provare_il_ramo_che_scatta]] continua a presentare il conto.

### Verifica del WORKFLOW #2 fatta da me, file per file

I numeri degli agenti reggono: **42 verdi, 0 falliti, 4 `#[ignore]`**.

| file | verificato da me |
|---|---|
| `live_linux_lifecycle` | 13 ok, 1 ignore |
| `live_linux_signals` | 8 ok |
| `live_linux_symbols` | 6 ok, 3 ignore (i tre stub) |
| `live_linux_expressions` | 9 ok |
| `live_linux_maps_modules` | 6 ok |

Totale test live Linux ora in albero: **103** (61 del workflow #1 + 42 del #2).

### Misure

| Dove | Esito |
|---|---|
| Windows `--lib` | **2127 / 0** |
| Linux `--lib` | **2108 / 0** |
| Linux live (lifecycle/breakpoints/watchpoints) | **44 / 0** — nessuna regressione dall'invariante |
| Darwin x2 | **0 errori** (sola compilazione) |


---

## WORKFLOW LINUX #3 — 2026-08-31 — il divario degli STUB, MISURATO

5 agenti su 5, zero errori. Aree: ELF, righe DWARF, heap, limiti di memoria,
limiti dello stepping. Questo giro non cercava difetti nuovi: doveva **quantificare**
i tre stub trovati al #2, e ci e' riuscito con verita' esterne (`nm`, `readelf`).

### `ElfSymbolProvider::parse_elf` — la perdita e' TOTALE e INCONDIZIONATA

Il commento in `elf_provider.rs` lo ammette: «This stub returns an empty provider
to avoid a full ELF parser dep.»

| forma dell'ELF | atteso (`nm`) | RAGGIUNGIBILE | ottenuto |
|---|---|---|---|
| no-pie -O0 -g (ET_EXEC) | 29 | **35** | **0** |
| PIE -O0 -g (ET_DYN) | 31 | **37** | **0** |
| no-pie, senza `-g` | 29 | **35** | **0** |
| strippato (`.dynsym`) | 2 | **3** | **0** |
| shared object `.so` (`.dynsym`) | 5 | **6** | **0** |

Quattro fatti che la cura deve rispettare, tutti misurati:

1. **Non fallisce: RIESCE e non restituisce nulla.** `parse_elf` accetta senza
   errore tutte e cinque le forme — per il chiamante e' indistinguibile da un file
   privo di simboli. (E il controllo dell'header e' reale: rifiuta i non-ELF e gli
   ELF troncati, quindi non e' un `Ok` incondizionato.)
2. **Identico con e senza `-g`** (35 contro 35): non e' un percorso legato al
   debug info.
3. **Colpisce il caso COMUNE**: la PIE e' il default di ogni distribuzione
   moderna, ed e' cio' a cui un debugger si attacca normalmente.
4. **Non serve un parser nuovo.** `parse_symtab`, gia' nel crate, legge
   correttamente i simboli sia in ET_EXEC sia in ET_DYN: manca solo la
   **camminata delle section header** (`e_shoff/e_shentsize/e_shnum/e_shstrndx`)
   per trovare `.symtab`/`.strtab` e `.dynsym`/`.dynstr` e delegare. Servono DUE
   tabelle, non una: la seconda e' l'unica presente negli strippati e nei `.so`.

Il bersaglio giusto e' la colonna RAGGIUNGIBILE, non quella di `nm`: la differenza
(29 contro 35) e' l'entry nulla all'indice 0 piu' le voci FILE/SECTION che `nm`
non stampa. Contabilizzata, non rumore.

### Il parser delle righe DWARF — rotto ESATTAMENTE sul default del compilatore

Stesso sorgente, stesso `cc -no-pie -O0 -g`, verita' esterna
`readelf --debug-dump=decodedline`:

| versione | byte `.debug_line` | righe del parser | indirizzi | readelf |
|---|---|---|---|---|
| 2 | 189 | 24 | 24 | 24 |
| 3 | 192 | 24 | 24 | 24 |
| 4 | 193 | 24 | 24 | 24 |
| **5** | 172 | **0** | **0** | **24** |

**Il default di `cc -g` su questa macchina e' la versione 5**, quindi il caso
rotto e' quello normale, non un bordo. Causa gia' scritta nel sorgente:
`parse_line_program_header` esce su v5 («v5 header layout differs — fallback») e
`parse_line_table` restituisce `Ok` con tabella **vuota**.

**Il modo di fallire e' il SILENZIO, non un errore** — verificato: nessuna
versione produce `Err`. E' la ragione per cui il difetto e' invisibile a monte.

Faccia visibile al consumatore: `DWARF 5: no line row covers line_alpha at
0x401136`, mentre lo stesso sorgente con `-gdwarf-4` risponde «riga 2 di
linefixture.c». E `0x401136` non e' teorico: e' l'indirizzo che stampa `nm` e su
cui un breakpoint scatta davvero.

Sulle versioni 2/3/4 il parser **non inventa nulla**: l'insieme dei suoi
indirizzi e' un sottoinsieme di quelli di `readelf` in tutte e tre.

### Nota di metodo degli agenti, che vale la pena tenere

L'asserzione e' scritta come **sottoinsieme**, non uguaglianza: `readelf` stampa
anche le righe di fine-sequenza, e pretendere l'uguaglianza avrebbe fatto fallire
il test per un non-difetto. Inventare un indirizzo che `readelf` non decodifica
resta comunque errore, ed e' quello che viene sorvegliato.

### Esiti dichiarati (da verificare dal coordinatore)

| file | esito |
|---|---|
| `live_linux_elf_symbols.rs` | 4 ok, 5 ignore (i 5 divari ELF) |
| `live_linux_dwarf_lines.rs` | 7 ok, 3 ignore (i 3 divari DWARF 5) |
| `live_linux_heap.rs` | 11 ok, 1 ignore |
| `live_linux_memory_limits.rs` | in verifica |
| `live_linux_stepping_limits.rs` | in verifica |


---

## Iterazione 648 — 2026-08-31 — `parse_elf` NON E' PIU' UNO STUB

Primo giro che **aggiunge una capacita' assente** invece di correggere un
comportamento.

### Il difetto

`ElfSymbolProvider::parse_elf` (`crates/rustre-symbols/src/elf_provider.rs:704`)
validava l'header e poi restituiva `Self::new(name)` — un provider VUOTO — col
commento che lo ammetteva: «This stub returns an empty provider to avoid a full
ELF parser dep.»

Il modo di fallire era il piu' insidioso: **non falliva**. RIUSCIVA e non
restituiva nulla, indistinguibile per il chiamante da un file davvero privo di
simboli.

### La cura, guidata dalla misura del workflow #3

Nessun parser nuovo: cammino delle section header
(`e_shoff/e_shentsize/e_shnum/e_shstrndx`), ricerca delle tabelle, e delega a
`SymtabParser` che gia' leggeva correttamente sia ET_EXEC sia ET_DYN.

**Rosso misurato** (ELF64 sintetico ma vero, costruito nel test, quindi gira
anche su Windows): `parse_elf returned 0 symbols []` per un file che contiene
`main` e `helper`.

### ⚠ La mia PRIMA implementazione funzionava, ed era SBAGLIATA

Da 0 simboli a 38, 43, 31. Sembrava un trionfo. I test degli agenti, che
confrontano con `nm`, hanno mostrato che ne restituivo **troppi**:

- 38 dove ne esistono 35
- 43 dove ne esistono 37

Causa: concatenavo `.symtab` e `.dynsym`. In un binario NON strippato il secondo
e' un **sottoinsieme** del primo, quindi ogni simbolo esportato finiva in lista
due volte. Il mio fixture aveva una sola tabella e non poteva coglierlo.

E' [[feedback_numero_che_sale_non_e_verifica]] applicata alla lettera: da 0 a 38
sembra un successo e nascondeva un difetto nuovo.

**Regola corretta**: `.symtab` VINCE quando c'e', `.dynsym` e' la riserva che
copre binari strippati e `.so`.

### Un test corretto, con la prova che sbagliava LUI

`parse_elf_should_load_the_dynsym_of_a_shared_object` asseriva
`obtained == reachable(.dynsym)` = 6, e otteneva 25. **Sbagliava il test**, e le
prove sono tre: quel `.so` e' compilato senza `-s` e quindi ha un `.symtab` di 25
voci; preferire la tabella completa e' cio' che fanno gdb e lldb; e il messaggio
del test stesso diceva `lost: false`, cioe' il simbolo esportato c'ERA.

Riscritta come **sovrainsieme** — la stessa nota di metodo che l'agente DWARF
aveva gia' applicato al confronto con `readelf`. Il test sul binario strippato
resta intatto e continua a inchiodare la riserva `.dynsym`: nessuna copertura
persa.

### Cinque `#[ignore]` RIMOSSI

I test che documentavano lo stub ora sorvegliano la capacita'. Un difetto chiuso
il cui test resta ignorato non sorveglia piu' nulla: e' una regressione
silenziosa in attesa.

### Misure

| Dove | Esito |
|---|---|
| `rustre-symbols --lib` | **654 / 0** |
| Windows `--lib` | **2127 / 0** |
| `live_linux_elf_symbols` (verita' esterna `nm`) | **9 / 0, zero ignorati** (era 4 ok + 5 ignore) |

### Restano aperti

- Parser righe DWARF: v5 da' 0 righe su 24, ed e' il default del compilatore.
- Watchpoint che non raggiunge i thread nati dopo l'armamento (`PTRACE_SEIZE`).
- 69 blocchi `unsafe` senza commento SAFETY.
- `apple_end_to_end` 2/4 rosso (percorso Apple, sotto sospensione iOS).


---

## ⭐ AUDIT COMPARATIVO x64dbg — 2026-08-31 — il documento piu' utile finora

Fornito dall'utente. Entrambi i debugger pilotati via i rispettivi MCP sullo
STESSO eseguibile (`notepad.exe`), due processi indipendenti.

**La proprieta' che lo rende decisivo: non serve una verita' esterna.** Due
debugger che guardano lo stesso stato del sistema operativo DEVONO produrre gli
stessi numeri. Dove concordano, entrambi sono giusti; dove divergono, almeno uno
sbaglia e si vede quale.

### PARTE I — Il motore e' CORRETTO. Zero discrepanze su 8 assi.

| asse | accordo |
|---|---|
| registri invarianti ASLR | **8/8 identici** (`rip` 0x7FFD701A0861 su entrambi) |
| moduli: basi | **15/15 identiche** |
| moduli: dimensioni | **15/15 identiche** |
| frame di stack | **5/5 identici** |
| byte di memoria | **32/32 identici** |
| indirizzo del breakpoint | identico |
| destinazione dello step | identica (4 byte, `sub rsp,0x28`) |
| codifica DR7 | **0x90001 bit per bit** |

I 4 registri che differiscono (rsp, rdi, r15, r8) sono stack/PEB/heap
per-processo, e `r8` mantiene lo STESSO delta da `rsp` (-8) su entrambi.

Le parti difficili sono giuste: **l'unwind `.pdata` senza frame pointer**
(`rbp = 0`, uno scanner ingenuo non ci arriverebbe), il **rewind di RIP dopo
l'int3**, la **codifica dei registri di debug**. E `original_byte: Some(72)` =
0x48, il prefisso REX.W corretto.

### PARTE II — I divari, tutti SOPRA il motore

Lo schema, e vale la pena nominarlo: **RustRE ha il dato grezzo e non fa
l'ultimo passo.**

1. 🔴 **Backtrace non simbolizzato** — `name: null` su tutti e 5 i frame, mentre
   x64dbg risolve `ntdll.LdrInitializeThunk+1DB`. Eppure `debug.modules` da'
   base e path per 15 moduli su 15: la export table basterebbe, senza PDB.
   `resolve_symbol` risponde «no symbols loaded» anche con la EAT di ntdll
   mappata e leggibile.
2. 🔴 **`debug.threads` da' UN campo (tid) contro NOVE** — x64dbg: cip, TEB,
   nome, handle, start_address, priority, suspend_count, last_error, number.
   Costo concreto: x64dbg mostra che i 3 thread non-main sono tutti a
   `cip 0x7FFD70171034` — il thread pool di ntdll, riconoscibile a colpo
   d'occhio. Con RustRE sono tre numeri. `GetThreadContext` e' gia' chiamato 38
   volte nello stesso file.
3. 🔴 **`LibraryLoad` con `path: ""` e `library_path: null`** — il campo e'
   stato AGGIUNTO e lasciato non popolato. Da risolvere con
   `GetFinalPathNameByHandle` sull'`hFile` di `LOAD_DLL_DEBUG_EVENT`.
4. 🔴 **`breakpoint_id: null`** per i watchpoint nella lista unificata
   `debug.breakpoints`, mentre `debug.watchpoints` assegna correttamente `wp_1`:
   il watchpoint non e' indirizzabile da li'.
5. 🔴 **Mappa di memoria senza semantica** — 156 regioni con tre booleani contro
   181 annotate con PEB, TEB per TID, Stack per TID, Heap per ID, sezioni PE
   (`.text`, `.rdata`, `.pdata`…), `state`/`type`/`protect` come stringhe.
   RustRE comprime `MEM_RESERVE` in `readable: false`, perdendo la distinzione
   fra «riservato non committato» e «committato ma PAGE_NOACCESS».
6. 🔴 **Nessun disassemblatore live** nella famiglia `debug.*`. Per disassemblare
   cio' che si sta debuggando bisogna uscire dal debugger.

### PARTE III — Dove RustRE vince

- **Autodiagnostica**: `debug.self_test` (7 sottosistemi) e `debug.health` che
  dichiara le capacita' **con la motivazione**, incluso cio' che NON sa fare.
  x64dbg non ha nulla di equivalente. Il **circuit breaker sul PDB** (apre dopo
  3 fallimenti per 60 s) e' ingegneria difensiva che x64dbg non espone.
- **Valutatore di espressioni tipato** via MCP: `*(u32*)($rsp + 8) + $rax` con
  cast di larghezza, e risposta in tre forme piu' `is_address`.
- **Path completi dei moduli** (WinSxS integrale), che x64dbg non da'.
- `ignore_count` e `only_thread`, che x64dbg non elenca.
- **95 tool `debug.*`** contro 24 dispatcher, con famiglie intere assenti in
  x64dbg: TTD, esecuzione inversa, analisi causale, retroattivo, NL, invarianti
  live, diff semantico fra run, multi-target.

### ⚠ L'AVVERTIMENTO DI METODO, da prendere sul serio

**Le famiglie TTD, causale e NL — ~30 tool su 95, un terzo della superficie —
NON sono state verificate dall'audit.** E due tool toccati (`heap_chunks`,
`set_watchpoint`) dichiarano di avere un **percorso non-live che restituisce
dati sintetici** quando manca la sessione. Onestamente documentato, ma:

> una risposta plausibile da quei tool non prova che il percorso live esista.

Sono **capacita' dichiarata, non misurata** — e in questo repo la distinzione fra
le due e' gia' costata piu' di una sessione. Il criterio per TTD, equivalente al
confronto con x64dbg: registrare una run, riprodurla, e verificare che il valore
letto al tick N coincida con quello che il processo aveva DAVVERO a quel punto.

### Nota: l'incoerenza dei parametri e' pari fra i due

L'auditor ha sbagliato 5 chiamate su 12 al primo tentativo anche su x64dbg
(`size` stringa ma `count` stringa, `"w"` invece di `"write"`). RustRE ha lo
stesso difetto (`set_watchpoint` vuole `size`, `read_memory` vuole `len`).
**Su questo asse sono pari, entrambi male.**

### Piano di lavoro che ne discende, in ordine di valore/costo

1. Simbolizzare il backtrace (EAT, senza PDB — il dato e' gia' in mano).
2. Popolare `debug.threads` da 1 a 5-6 campi.
3. `LibraryLoad`: risolvere il path.
4. `breakpoint_id` per i watchpoint nella lista unificata.
5. Etichette semantiche nella mappa di memoria.
6. Disassemblatore live.
7. **Verificare TTD/causale/NL sul percorso LIVE**, non solo che i tool
   rispondano.


---

## WORKFLOW LINUX #4 — 2026-08-31 — ⭐ RISPONDE ALL'AVVERTIMENTO DELL'AUDIT

5 agenti su 5, zero errori. **Questo giro chiude il buco che l'audit x64dbg aveva
nominato come piu' grave**: «le famiglie TTD, causale e NL non sono state
verificate — sono capacita' DICHIARATA, non misurata».

**Ora sono misurate**, su processo vero, e il verdetto e' articolato: la maggior
parte funziona davvero, e i difetti hanno un nome.

### TTD / esecuzione inversa — 23 test, 20 verdi, 3 difetti

**Cio' che funziona DAVVERO** (non e' piu' capacita' dichiarata):
registrazione live (40 stati, primo pc == `main`), **`step_backward` che
restituisce ESATTAMENTE i pc misurati da ptrace** per tutta la traccia
all'indietro, `AtBeginning` a inizio traccia, `seek` fra due posizioni,
`reverse_continue` su un pc realmente visitato che atterra su pc **e** sequenza
giusti, **`who_wrote`/`last_writer` che nominano l'istruzione dentro `main` che
ha scritto `g`** (0x11 poi 0x22, due pc distinti), copertura dei byte interni
(`g+1..3` si', `g+4` no), `trace_origin_full`, `retro_print` che rende `rip`/`rsp`
reali per ogni scrittura.

**I 3 difetti, col rosso misurato:**

1. **`reverse_continue` INVENTA uno stop.** Andando indietro senza colpire nulla
   restituisce `states[0]` con `stop_reason == "recorded"` — indistinguibile da
   un hit vero.
   Rosso: `reverse_continue to an unvisited pc must be distinguishable from a
   hit; got pc=0x40187a reason="recorded"`.
   ⚠ La cura esiste gia' **nello stesso modulo**: il ramo senza backend
   (`simulated_reverse_continue_to_beginning`) dice correttamente «inizio
   storia». gdb risponde «No more reverse-execution history».
2. **`reverse_step_over` e' cieco al frame** — aliasato a `step_backward`.
   Rosso: `reverse_step_over from inside callee must leave [0x401865,0x40187a);
   it returned 0x401870`. Raggiungibile con cio' che c'e': la registrazione ha
   ogni pc, basta risalire al primo fuori dal range di `callee`.
3. **`run_to_previous_call` non cerca alcuna call** — aliasato anch'esso.
   Rosso: `run_to_previous_call returned 0x404d28, which objdump does not list
   as a call site`.

### Tracepoint — 16 test, ZERO difetti di logica, ma una CAPACITA' NON CABLATA

Nessun `#[ignore]`: la logica di tracepoint e condizioni e' corretta su stato
vivo in ogni sua parte. **Il divario e' il cablaggio.**

Verita' interna, coi comandi che la producono:
- `grep -rn "TracepointSet" src --include=*.rs | grep -v conditional_breakpoint.rs` → **nessun output**
- `grep -ci "tracepoint" src/linux_debugger.rs` → **0**

| | atteso (gdb `dprintf`) | raggiungibile oggi | ottenuto |
|---|---|---|---|
| comando per armarlo | uno | nessuno: `set_breakpoint` + ciclo scritto a mano | ~25 righe per sito |
| **fermi del tracee su 5 attraversamenti** | **0** | 5 | **5** |
| rendering da stato vivo | corretto | corretto | corretto, 5/5 distinti |

Cioe': **il contratto del tracepoint e' NON-STOPPING e il backend ferma 5 volte
su 5.** `Tracepoint`/`TracepointFormat`/`TracepointSet` funzionano, ma nessun
backend li conosce. Cura scrivibile: `set_tracepoint(addr, format)` sul trait
piu' un ramo in `condition_allows_stop` (`linux_debugger.rs:~735`) che fa
`fire_at` e restituisce `false` — l'unico punto che ha gia' registri, `pc`/`sp` e
il lettore di memoria che una render richiede.

### ⭐ UN AGENTE HA FALSIFICATO I PROPRI TEST, e va imitato

L'agente dei tracepoint ha cambiato **un solo dato** della verita' esterna
(`22`→`23` fra gli argomenti attesi) e ha misurato: `7 passed; 9 failed`.
**Nove test su sedici mordono davvero il valore vivo**; i 7 restanti non
dipendono da quel dato per costruzione (contratto non-stopping, indirizzo mai
raggiunto, igiene). E' la prova che i test non sono vacui — cfr.
[[feedback_verde_non_significa_verificato]]. Da fare in ogni giro futuro.

Nota: lo stdout del tracee stesso (`80 75`) e' verita' esterna indipendente —
1+8+15+22+29 = 75 e la somma dei (x+1) = 80.


---

## Iterazione 649 — 2026-08-31 — TRE tool INVENTAVANO lo stato del processo

Nasce dall'avvertimento finale dell'audit x64dbg: «una risposta plausibile da
quei tool non prova che il percorso live esista». L'utente ha chiesto di
chiuderlo. Scavando, i tool che fabbricavano erano **tre**, non i due che l'audit
aveva toccato.

### Il peggiore: `debug.backtrace`

Su una sessione **mai aperta** rispondeva con uno stack completo:

```
main            @ target.exe   +0
BaseThreadInitThunk @ kernel32.dll +69
RtlUserThreadStart  @ ntdll.dll   +32
```

indirizzi plausibili, offset, catena SP coerente — **indistinguibile da un
backtrace vero**. E **non impostava nemmeno `live: false`**: il campo mancava,
quindi chi lo controllava per difendersi non vedeva «falso», non vedeva nulla.

Un backtrace e' la risposta che si legge PER PRIMA quando qualcosa e' andato
storto. Un backtrace inventato e' la bugia meno dubitabile che questo strumento
potesse dire.

### Gli altri due

- **`debug.current_thread`** → `ThreadId(1)`, un tid indistinguibile da uno vero,
  ed e' il thread predefinito su cui ricadono registri e stepping.
- **`debug.heap_chunks`** → un'arena di due chunk a `0x1000`, con gli **stessi
  nomi di campo** del percorso vivo.

### ⭐ Il crate si CONTRADDICEVA, e la prova e' nello stesso file

`lib.rs` ha gia' una guardia anti-fabbricazione che verifica che **sei** tool
rifiutino la sessione mai aperta `sess_001`. `debug.backtrace` **non era nel suo
elenco** — e quaranta righe piu' sotto `test_debug_backtrace_frames`
**PRETENDEVA** che `backtrace` fabbricasse per quella stessa sessione.

Un file, due test, richieste opposte.

**Cura**: la guardia canonica ora ne copre **nove** (i tre corretti sono dentro),
e il test che esigeva la finzione ora verifica il rifiuto. Non e' piu' un mio
test isolato a sorvegliarli: e' il controllo canonico del crate.

### Le DESCRIZIONI mentivano, ed e' meta' del difetto

`debug.set_watchpoint` era gia' stato corretto nel codice in un giro precedente,
ma la sua descrizione continuava a promettere «without a live session returns the
computed register layout». **E' cosi' che l'auditor l'ha classificato come tool
che fabbrica**: leggendola. Una documentazione che sopravvive alla correzione del
codice produce diagnosi sbagliate su un sistema sano — e qui l'ha fatto con un
lettore esperto e attrezzato. Corrette entrambe (`heap_chunks` e
`set_watchpoint`).

### Cosa NON ho toccato, e perche'

`debug.evaluate` (ripiega su espressioni costanti) e `debug.load_symbols`
(analizza un file di simboli) riportano anch'essi `live: false`, ma **non
fabbricano**: fanno lavoro vero che non richiede un processo, e non fingono di
descriverne uno in esecuzione. Distinguere i due casi e' il punto; togliere anche
questi sarebbe stato zelo, non rigore.

### Due test miei sono caduti, ed era giusto

Entrambi **verificavano la finzione**:
1. `test_debug_backtrace_frames` (preesistente) → riscritto per verificare il rifiuto.
2. `backtrace_publishes_the_frame_pointer_including_its_absence` (mio, §643) →
   usava il percorso di esempio. Sostituito con un controllo sui sorgenti, che e'
   **piu' debole**: garantisce che il renderer vivo porti ancora il campo come
   nullable, non che il valore arrivi giusto al chiamante. **La garanzia
   comportamentale su `fp` ora esiste solo dove c'e' un processo vero.** Scritto
   nel doc del test invece che lasciato intendere: una copertura che si
   indebolisce in silenzio e' il modo tipico in cui una suite smette di
   sorvegliare.

### ⭐ Un mio guard di 15 giri fa ha colto il suo autore

`a_source_guard_cannot_match_its_own_test_text` (§634) e' scattato sul mio nuovo
controllo: cercava una stringa che compare **anche nel proprio testo**, quindi
sarebbe stato verde perfino se il renderer avesse perso il campo. Risolto con
`production_only`, l'helper scritto apposta al 634 dopo esserci cascato tre
volte. Queste guardie non proteggono dal codice: proteggono da chi scrive i test.

### Osservazione: un test dipendente dall'ORDINE

`mcp_detach_clears_hardware_watchpoints` e' fallito in un run completo e passa da
solo e nei run successivi: i test MCP condividono un registro di sessioni globale
e girano in parallelo. Non e' una mia regressione, ma **un test che dipende
dall'ordine e' una regressione in attesa**. Annotato come fronte aperto.

### Misure

| Dove | Esito |
|---|---|
| MCP | **409 / 1** — passati 407 → 409, l'1 e' il cricchetto |
| Windows `--lib` | **2127 / 0** |
| Linux `--lib` | **2108 / 0** |
| Darwin x2 | **0 errori** (sola compilazione) |


---

## ⭐⭐ WORKFLOW LINUX #5 — LA FALSIFICAZIONE — il risultato piu' importante della sessione

Un agente ha cambiato **un solo dato di verita' esterna** in ciascuno dei 20 file
live esistenti e ha misurato quanti test cadono. Ripristino verificato: i 20 file
sono **byte-identici** al backup (`cmp` su tutti e 20).

### Il numero

| | |
|---|---|
| test live totali | **230** |
| attivi (non `#[ignore]`) | **211** |
| **che MORDONO davvero** | **68** |
| **VACUI sul dato mutato** | **143** |

Avvertenza dell'agente, corretta: «vacuo» significa *non morde su QUEL dato*, non
«inutile». `read_memory_at_an_unmapped_address_fails` non deve dipendere da un
indirizzo di simbolo. **I casi gravi sono quelli il cui NOME afferma la
dipendenza.**

### I tre file gravi, con la causa LETTA

**1. `live_linux_breakpoints.rs` — 18 vacui su 20. Il ciclo e' chiuso su se
stesso.** `run_until_breakpoint(dbg, addr, ..)` **FILTRA** il flusso degli stop
sull'indirizzo che il test poi asserisce: `assert_eq!(address, fx.hot)` e' una
**tautologia**. Qualunque indirizzo mappato, eseguibile e attraversato la
soddisfa. Forzando ogni simbolo a risolvere a `main`, 20 test su 20 restano
verdi. Fra i vacui:
`a_planted_breakpoint_stops_the_process_and_is_reported_as_a_breakpoint`,
`set_breakpoint_writes_the_trap_into_the_live_text_segment`,
`enable_breakpoint_replants_the_trap_after_a_disable`.

**2. `live_linux_load.rs` — 8 su 8 vacui.** Stesso helper, stessa causa. Incluso
`two_hundred_breakpoints_plant_and_remove_restore_the_text_byte_for_byte`.

**3. `live_linux_elf_symbols.rs` — 9 su 9 vacui: L'ORACOLO E' DECORATIVO.**
`Gap::expected` — il conteggio di `nm`, unico oracolo indipendente del file —
compare **solo dentro argomenti di `format!`, in nessuna asserzione**. Le
asserzioni confrontano `obtained` con `reachable`, **entrambi calcolati dagli
stessi byte**. Forzando `nm_count` a 0, restano 9/9 verdi.

### ⚠ QUESTO INDEBOLISCE IL MIO GIRO 648, e va detto

Al §648 ho dichiarato `parse_elf` corretto «verificato contro `nm` su cinque
forme di ELF». **Quei test non confrontavano con `nm`.** La capacita' e' reale —
il guard NUOVO dell'agente, `parse_elf_resolves_every_name_nm_defines`, rende
`nm` portante e **passa**, risolvendo tutti e 28 i nomi — ma la mia frase
descriveva una verifica che non stava avvenendo. Ho creduto a un verde che non
guardava l'oggetto.

### La cura dell'agente: un oracolo che nessuna manomissione puo' falsificare

Il perno e' **contare gli attraversamenti SENZA filtrare sull'indirizzo**: la
fixture chiama `hot` 5 volte, `warm` 1, `cold` 0. La tripla **(5,1,0)** e'
riprodotta da una sola assegnazione indirizzi→nomi, e nessuna manomissione della
tabella dei simboli puo' falsificarla. Otto test-guardia, tutti falsificati a
loro volta: 5 mutazioni, **7 su 8 mordono**.

**L'ottavo e' andato rosso alla PRIMA esecuzione trovando un difetto in se
stesso**: `pgrep -f falsif` intercettava il binario di test di cargo
(`live_linux_falsification-<hash>`) invece della fixture. Corretto in
`pgrep -x falsifwf5`.

**E un'asserzione debole trovata cosi' e sostituita**: la prima versione di
`parse_elf_resolves_every_name_nm_defines` confrontava CONTEGGI
(`obtained >= nm_count`), e forzare l'oracolo da 28 a 31 la lasciava verde
perche' `parse_elf` ne restituisce comodamente di piu'. **Un conteggio e' lasco,
l'insieme dei NOMI no.**

### Stato finale delle 21 suite: 21 su 21 verdi, 0 rossi, 0 orfani

### Lezione, da applicare sempre

Un test che costruisce l'aspettativa **dallo stesso dato che verifica** non
verifica: e' un'identita' scritta in due righe. La falsificazione — cambiare un
dato e pretendere il rosso — e' l'unico modo per distinguerla da una misura.
Vedi [[feedback_verde_non_significa_verificato]] e
[[feedback_guardie_che_si_rompono_da_sole]].


---

## Iterazione 650 — 2026-08-31 — il backtrace ora NOMINA i frame

Primo dei sei divari dell'audit x64dbg: ogni frame riportato con `name: null`
mentre x64dbg rispondeva `ntdll.LdrInitializeThunk+1DB`.

### Lo schema dell'audit, confermato ancora una volta

**Il pezzo difficile c'era gia'.** `resolve_via_module_exports` legge le export
table dei moduli caricati e le riallinea alla base di runtime — che e' la parte
dove si sbaglia, perche' un RVA sommato alla base sbagliata da' un numero
plausibile che non punta a niente. Ma serviva solo per **nome → indirizzo**. Il
verso che il backtrace richiede, **indirizzo → nome**, non era mai stato scritto.

Esisteva perfino un test, `resolve_symbol_falls_back_to_the_exports_already_mapped`,
che elencava «quattro pezzi presenti e non uniti».

### La regola di scelta, e le tre forme di errore che fissa

`nearest_export_at_or_below` non e' banale, e ogni modo di sbagliarla produce un
NOME PLAUSIBILE invece di un errore:
- **al di sotto o uguale, mai al di sopra**: nominare un frame con l'export che
  lo SEGUE indica codice che non e' stato eseguito;
- **il PIU' GRANDE fra quelli sotto**, non il primo trovato: un modulo ne ha
  centinaia, e tutti quelli sotto sono «un» match mentre solo il piu' vicino e'
  la funzione in cui l'indirizzo si trova;
- **niente sotto ⇒ `None`**, non il primo export: un indirizzo che precede ogni
  export non e' dentro nessuno di essi, e un nome sarebbe invenzione.

Filtrati anche i **forwarder**: il loro indirizzo non e' codice di questo modulo
e userebbe l'ancora sbagliata per i frame vicini.

### L'ORDINE non e' una preferenza

Il ripiego gira **dopo** il fornitore di simboli e solo dove quello ha taciuto.
Le export nominano solo cio' che un modulo esporta, quindi una funzione statica
verrebbe attribuita all'export che la precede — nome plausibile, funzione
sbagliata. Per ultimo significa che un nome da PDB vince sempre.

### ⭐ Il guard di prossimita' mi ha fermato per la TERZA volta, e la terza ho capito

Le prime due volte ho spostato prosa. La terza ho letto il messaggio:
`line 1736: the reply claims Debugger::backtrace but nothing in the preceding 60
lines calls it`. La chiamata era a 1668, la dichiarazione a 1736: **68 righe**.

Il guard misura la prosa ma **segnalava altro**: il gestore era cresciuto troppo
perche' ci stavo infilando tutta la logica di arricchimento. Cura giusta:
estrarre **`enrich_frame`** in una funzione con nome e doc. Ora il gestore fa tre
righe e la gerarchia delle fonti ha una sede unica.

Le prime due volte ho curato il sintomo.

### ⭐ E il MIO guard e' andato rosso PER IL MOTIVO GIUSTO

Il controllo sui sorgenti del `fp` cercava entro 6000 caratteri dal tool
`debug.backtrace`; spostato il rendering, non guardava piu' l'oggetto.

**Ma l'esito interessante e' il contrario**: con una finestra piu' larga sarebbe
rimasto **VERDE continuando a guardare codice sbagliato**. La differenza fra
«mi avverte» e «mi mente» dipendeva solo da quanti caratteri avevo scelto.
Riancorato a `fn enrich_frame(` — al NOME della cosa sorvegliata, non alla sua
posizione.

### Tre correzioni di tipo, tutte figlie dell'estrazione

Riferimento condiviso invece di esclusivo (la funzione legge soltanto), tipo
concreto `CodeViewProvider` invece di oggetto-trait, e `use SymbolProvider` reso
esplicito perche' il gestore lo importava localmente. Errori a rischio nullo — il
compilatore li prende tutti — ma sono il prezzo prevedibile di un'estrazione.

### Misure

| Dove | Esito |
|---|---|
| MCP | **410 / 1** — passati 409 → 410, l'1 e' il cricchetto |
| Windows `--lib` | **2127 / 0** |
| Linux `--lib` | **2108 / 0** |
| Darwin x2 | **0 errori** (sola compilazione) |


---

## Iterazione 651 — 2026-08-31 — `debug.threads`: da UN campo a sei

Secondo dei sei divari dell'audit x64dbg: **nove campi per thread la', UNO qui**.

Il costo e' concreto e l'audit lo mostra: x64dbg fa vedere che tre thread su
quattro stanno allo stesso `cip` con lo stesso start address — sono il thread
pool di ntdll, riconoscibili a colpo d'occhio. **Quattro numeri nudi non nominano
nulla.**

### La causa e' DIVERSA dai giri precedenti

Negli altri casi il dato era gia' in mano e non veniva usato. Qui **non esisteva
nel contratto**: `threads()` restituisce `Vec<ThreadId>` e basta, quindi nessun
livello superiore poteva riportare di piu' per quanto il backend sapesse.

### La forma della cura conta quanto la cura

`thread_details()` aggiunto al trait con un **default che dichiara la poverta'**
— restituisce i soli id — invece di inventare. Ogni campo di `ThreadInfo` e'
`Option`: un backend risponde cio' che sa leggere e tace sul resto. E' la stessa
disciplina a tre stati che oggi ha chiuso il frame pointer inventato (§638), il
PID che diventava il sentinella di «nessun processo» (§640), il `dr7` assente
letto come pulito (§641-642) e i tre tool che fabbricavano lo stato (§649).

**Rosso misurato**, la poverta' esibita:
`ThreadInfo { id: ThreadId(22228), pc: None, base_priority: None, start_address: None, teb: None, name: None }`
— un id e cinque assenze, su un processo FERMO in cui `get_registers` funziona.

### Su Windows, due campi che il codice AVEVA GIA'

- **`base_priority` non costa una query**: `threads()` cammina gia' su
  `THREADENTRY32`, il cui `tpBasePri` veniva riempito dal sistema e **scartato**
  da noi. Terza volta oggi che lo schema dell'audit si ripete — il lavoro
  difficile fatto, l'ultimo passo mancante.
- **`pc`** da `get_registers`, valido proprio perche' il processo e' fermo. Un
  thread il cui contesto non si legge conserva `None`, non uno zero plausibile:
  un pc a 0 si leggerebbe come «thread fermo a un indirizzo nullo».

Il test asserisce anche che `thread_details` descriva **gli stessi** thread di
`threads()`: e' un sovrainsieme, non una seconda enumerazione che puo' divergere.

### Cio' che NON ho fatto, e perche'

- **Suspend count** (che x64dbg mostra): ottenerlo richiede una coppia
  sospendi/riprendi, che **PERTURBA IL PROCESSO OSSERVATO**. In un debugger e' un
  costo da dichiarare, mai da pagare di nascosto per riempire un campo — chi
  legge il valore non saprebbe che ottenerlo ha cambiato lo stato esaminato.
- **TEB, start_address, name**: richiedono `NtQueryInformationThread` e
  `GetThreadDescription`, API nuove con la loro gestione degli errori. Meglio un
  giro dedicato che infilarle qui e verificarle male.

### MCP aggiornato al backend nuovo

`debug.threads` riporta ora `tid`, `pc`, `base_priority`, `start_address`, `teb`,
`name`. I campi non risposti restano **`null`**.

### Misure

| Dove | Esito |
|---|---|
| Windows `--lib` | **2128 / 0** |
| Linux `--lib` | **2108 / 0** |
| Darwin x2 | **0 errori** (sola compilazione) |
| MCP | **409 / 1** — l'1 e' il cricchetto |

### Il guard di prossimita' ha trovato un'AFFERMAZIONE FALSA, non una prosa lunga

Le tre volte precedenti mi aveva segnalato commenti fuori posto. Qui ha colto un
difetto sostanziale: la risposta dichiarava
`source: "rustre_debug::Debugger::threads"` mentre il gestore ora chiama
`thread_details`. **La dichiarazione era rimasta indietro rispetto al codice** —
stessa classe delle descrizioni corrette al §649, per cui un auditor esperto
aveva tratto una diagnosi sbagliata leggendole. Il campo `source` esiste per dire
al chiamante da dove viene il dato: una dichiarazione stantia li' e' peggio
dell'assenza.


---

## ⭐ WORKFLOW #6 — DE-VACUAZIONE — i test vacui ora MORDONO

5 agenti su 5. Seguito diretto della campagna di falsificazione (143 vacui su
211). I due file peggiori sono chiusi, e **entrambi gli agenti hanno trovato un
difetto NEL PROPRIO lavoro** falsificandolo.

### `live_linux_breakpoints.rs` — da 18 vacui su 20 a 20 mordenti su 21

**Causa riprodotta prima di toccare nulla**, non dedotta: rieseguita la
mutazione della campagna (ogni simbolo risolve a `main`) → **18 passed / 2
failed**, esattamente il numero dichiarato. I 2 che gia' mordevano lo facevano
per il **conteggio**, non per l'indirizzo.

Cura: `run_until_breakpoint(dbg, addr, ..)` — che filtrava gli stop
sull'indirizzo poi asserito — sostituito da helper che **non prendono
l'indirizzo**. `assert_eq!(address, fx.hot)` torna a essere una misura invece di
una tautologia. Piu' **due oracoli indipendenti** sullo stesso ELF (`nm` e
`objdump -d --disassemble`) che devono concordare, e il confronto dei **32 byte**
del codice vivo nel tracee col corpo disassemblato.

**Quattro falsificazioni, misurate:**

| mutazione | rossi |
|---|---|
| ogni simbolo → `main` | **21 / 21** |
| `hot` riceve l'indirizzo di `warm`, oracoli concordi | **20 / 21** |
| la fixture chiama `hot` 4 volte invece di 5 | 4 |
| la fixture chiama `warm` 2 volte invece di 1 | 1 |

⚠ **Difetto trovato dall'agente NEL PROPRIO lavoro**: la prima versione
confrontava 8 byte, cioe' **il prologo che `hot`, `warm` e `cold` condividono** —
lasciava 17 verdi su 21 sotto mutazione. Allargata la finestra a 32 byte: 20 su
21.

**L'unico sopravvissuto e' DICHIARATO invece che nascosto**:
`a_condition_on_an_unset_address_is_refused` non dipende da quale funzione sia
quell'indirizzo, perche' asserisce cosa accade dove NON c'e' breakpoint. Non e'
debolezza.

### `live_linux_load.rs` — da 8 vacui su 8 a 8 mordenti

**Causa diversa, stessa radice**: il file non usa l'helper filtrante — nessun
test chiedeva mai se `fx.hot` fosse davvero `hot`. Una trappola si pianta e si
ripristina byte per byte a **qualunque** indirizzo eseguibile mappato: erano
affermazioni su «un indirizzo eseguibile qualsiasi».

Cura: contare gli attraversamenti senza filtrare, con una **matrice** letta dal
sorgente della fixture:

| modo | `hot` | `filler` |
|---|---|---|
| senza argomenti | 0 | 1 |
| `loop 5` | 5 | 0 |

⚠ **E anche questo guard e' andato rosso alla prima esecuzione, su se' stesso**:
```
[pin-falsify] loop 5: hot=5 main=1; quick: main=1
assertion `left != right` failed: the crossing count does not separate `main` from `filler`
  left: 1   right: 1
```
Una **cella sola** non separa `main` da `filler`; la **coppia** si': `main` =
(1,1), `filler` = (1,0), `hot` = (0,5). E' la lezione «un conteggio e' lasco,
l'insieme no» misurata una seconda volta, su un oggetto diverso.

Rafforzata anche una soglia lasca preesistente: `trap_count >= n - 1` →
`trap_count == n` (misurato **200/200**), piu' il controllo che la finestra
pristina non sia gia' tutta `0xCC` — altrimenti «osservo trappole» non prova
nulla.

### La lezione, confermata due volte in un giro

**Chi scrive un oracolo deve falsificare anche l'oracolo.** Entrambi gli agenti
hanno prodotto una prima versione che sembrava rigorosa e non lo era: una
guardava byte condivisi da tutte le funzioni, l'altra una cella che due simboli
diversi riproducono. Nessuna delle due sarebbe mai stata scoperta da un run
verde.


---

## Iterazione 652 — 2026-08-31 — `LibraryLoad` dice finalmente QUALE libreria

Terzo dei sei divari dell'audit. **Rosso misurato: `left: 0, right: 7`** — sette
librerie caricate, zero nominate.

### Perche' era sopravvissuto a piu' tentativi di cura

Non era «un campo aggiunto e dimenticato», come sembrava da fuori:
`resolve_library_path` **esiste ed e' collegata in CINQUE punti** dell'MCP. E il
backend riempie gia' il nome sul lato asincrono in `arm_pending_breakpoints`, con
tanto di guardia che lo pretende.

**La ricerca era corretta, la FONTE sbagliata.** Entrambe cercano il modulo per
base in `modules()`, ma a `LOAD_DLL_DEBUG_EVENT` il loader **non ha ancora
registrato l'immagine**, quindi toolhelp non la elenca. Nessuna delle due poteva
funzionare, e nessuna delle due era scritta male.

### Il dato era in mano, e veniva buttato via

Windows consegna `hFile` **insieme all'evento**, proprio perche' in quell'istante
e' l'unica cosa che nomina l'immagine. Questo backend quell'handle lo prendeva
gia' — `event_file_handle` — **solo per chiuderlo**, in una correzione precedente
che tappava una perdita di handle. Lo schema dell'audit nella sua forma piu'
pura: il datum preso in mano e non interrogato.

Cura: `GetFinalPathNameByHandleW` sull'handle, **fuori** da `classify_event`,
nel ciclo di debug dove l'handle e' gia' posseduto. Prefisso `\?\` rimosso: e'
una fuga per la lunghezza del path, non parte del nome.

### ⚠ Il rischio dichiarato PRIMA, e la misura che lo chiude

La guardia `classify_event_does_not_query_the_traced_process` fu stabilita **per
bisezione** all'iterazione 504: una query psapi in quella finestra ruppe il
rilevamento dei watchpoint hardware, e ogni hit tornava come single step perche'
`DR6` non risultava piu' impostato.

Il mio argomento — un handle di FILE non e' il processo tracciato: niente handle
di processo, niente psapi, niente toolhelp — e' **un argomento, non una prova**.
Ho scritto nel commento che il controllo che conta sono i test sui watchpoint, e
li ho eseguiti in modo esplicito:

```
a_debug_register_hit_is_reported_as_a_breakpoint_not_a_single_step ... ok
hardware_debug_registers_round_trip ... ok
every_backend_programs_the_debug_registers_for_watchpoints ... ok
a_disarm_that_cannot_clear_the_debug_registers_does_not_report_success ... ok
```

**Otto controlli sui registri di debug, tutti verdi.** La distinzione ora e'
misurata sul test che la puo' falsificare, non solo ragionata.

### Misure

| Dove | Esito |
|---|---|
| Windows `--lib` | **2129 / 0** |
| Linux `--lib` | **2108 / 0** |
| Darwin x2 | **0 errori** (sola compilazione) |
| MCP | **410 / 1** — l'1 e' il cricchetto |

### Stato dei sei divari dell'audit x64dbg

| # | divario | stato |
|---|---|---|
| 1 | backtrace non simbolizzato | **CHIUSO** §650 |
| 2 | `debug.threads` 1 campo contro 9 | **CHIUSO** §651 (6 campi) |
| 3 | `LibraryLoad` con path vuoto | **CHIUSO** §652 |
| 4 | `breakpoint_id: null` per i watchpoint | aperto |
| 5 | mappa di memoria senza semantica | aperto |
| 6 | disassemblatore live assente | aperto |

Piu' l'avvertimento sui ~30 tool mai provati dal vivo: **superato** dal workflow
#4, che ha misurato la famiglia TTD su processo vero (20 capacita' reali, 3
difetti con nome e rosso).

---
---

# ARCHIVIO — le versioni che le riscritture avevano CANCELLATO

> **Perché questa sezione esiste.** La regola di questo repo è: *aggiungere
> sempre, non togliere mai*. Alle iterazioni **614**, **618** e **624** ho
> riscritto questo file **da zero**, seguendo l'istruzione del ciclo «ogni 4
> round riscrivilo da zero» e cancellando ogni volta ciò che c'era prima. Era
> sbagliato: la regola dell'utente prevale, la lunghezza non è un problema, e
> quelle riscritture hanno distrutto informazione — misure, cause, regressioni.
>
> Recuperate da git al **628** e riportate qui integralmente. Da qui in avanti
> questo file **cresce soltanto**: ogni round aggiunge, nessun round toglie.


## Stato immediatamente PRIMA della riscrittura del 614

<!-- recuperato da git: 685230a05^ -->

## rustre-debug — stato misurato

> **Regola.** Ogni 4 iterazioni questo file va riscritto DA ZERO. È un cruscotto,
> non un registro. Precedente: 608. Questa: **613**.
>
> **Ogni numero è misurato.** «Non dimostrato» = nessuna macchina raggiungibile
> ha risposto: lacuna dichiarata, non dettaglio.

---

### 1. Semaforo

| Dove | Verificato come | Esito |
|---|---|---|
| Windows x86_64 | suite locale | **2036 / 0** |
| Windows ARM64 | CI `windows-11-arm` | **da 22 errori a 0 attesi** (602 + 606); non ancora confermato |
| Linux x86_64 | WSL + CI | **2017 / 0** |
| Linux aarch64 | CI `ubuntu-24.04-arm` | **2009 / 3** — da 6, poi 5, ora 3 |
| macOS Intel / Apple Silicon | CI | suite e live test **verdi**; step MCP rosso per un cricchetto altrui |
| iOS Simulator | CI `macos-14`, arm64 reale | **verde** |
| iOS, giri avversariali | `/workflows` | giro 6: **77 agenti, 9 confermati / 9 chiusi / 0 falsi positivi**; giro 7 in corso |
| iOS device | CI | compila e **linka i test**; non esegue (serve hardware) |
| MCP | locale + CI | 392/0 su Windows; su Linux **compila per la prima volta** (605) |
| Darwin ×2 | `cargo check` | 0 errori |

### 2. Cosa funziona oggi che non funzionava ieri

- **Breakpoint software su macOS**: non funzionavano affatto (`mach_vm_protect`
  mancante, 579). Ora le due righe macOS sono verdi live inclusi.
- **Watchpoint dati e breakpoint hardware su ARM64 Linux** (570, 571), con
  l'`ENOSPC` che ne bloccava cinque test chiuso (589) e l'indirizzo staged
  conservato (594).
- **macOS riporta l'indirizzo di fault** (595): prima diceva «è crashato» e mai
  «dove».
- **Windows ha una CI** (597) — prima era verificato su una macchina sola — e il
  backend **compila per ARM64** (602, 606), cosa che nessuno aveva mai provato.
- **Sei tool MCP Linux riparati** (605): `linux_debug.rs` non compilava, quindi
  l'intera suite MCP non girava su Linux.
- **Un nome di registro stretto legge il valore stretto** (613). Il ponte MCP
  accettava un nome stretto preponendogli `r`: giusto per `ax`→`rax`, assurdo
  per `eax`→`reax`. Misurate DUE risposte sbagliate diverse dalla stessa riga:
  `eax` risultava **assente**, `ax` restituiva tutti e 64 i bit di `rax`. Non è
  cosmetico — i due consumatori sono i breakpoint condizionali e
  `debug.evaluate`, quindi decide se l'esecuzione si ferma: `ax == 0x1234` non
  scattava mai mentre il registro valeva davvero `0x1234`. Ora
  `read_register_by_name` conosce la larghezza che ogni nome significa, incluse
  le viste `ah` (bit 8..16), i suffissi `r9d`/`r9w`/`r9b` e le `w0..w30` ARM64.
- **Una scrittura ai registri `fp`/`lr`/`x29`/`x30` non viene più scartata** (612).
  I tre backend pubblicano ENTRAMBE le grafie in lettura e ne preferivano una in
  scrittura — Windows `fp`, macOS e Linux `x29` — quindi un normale
  leggi-modifica-riscrivi attraverso l'altra grafia veniva sovrascritto dal
  valore stale e `set_register` riportava successo. Tre copie, tre preferenze
  diverse: famiglia 2 allo stato puro. La decisione ora sta in
  `aliased_register_write`, in `lib.rs`, dove **è testabile** — i due file
  colpevoli sono `cfg`-gated a target che questa macchina non compila.
- **L'MCP dice quattro verità nuove**: `"note"` sui watchpoint non riarmati
  (568), `capabilities` col motivo di ogni assenza (577), `"fault"` portabile
  (582), `library_path` risolto (601).

### 3. Le tre famiglie di difetti che questo crate produce

1. **Un fallimento riportato come successo**: `let _ =`, `else { continue }`, un
   `bool` in cui «non trovato» e «non riuscito» collassano, uno step CI
   `continue-on-error` il cui esito non risale, una scrittura dimensionata male,
   un `Drop` che lascia una trappola in silenzio.
2. **Logica condivisa che deriva**: fra i tre backend, fra backend e MCP, fra i
   due lati dello stesso test, fra una capacità DICHIARATA e il codice che la
   nega.
3. **Un'assunzione x86 in codice che gira anche su ARM**: byte di trappola,
   allineamento, nomi dei registri, PC al trap, PAC, numero di slot, trap flag.

### 4. Difetti aperti — dichiarati

| Cosa | Dove | Stato |
|---|---|---|
| **PAC nell'unwinder** | Linux ARM | 573 e 591 erano entrambi **codice morto**; il 607 lo legge per primo. Non ancora misurato |
| **2 test sui registri di debug** | Linux ARM | `NT_ARM_HW_WATCH` sembra fallire su quel runner: da capire, non da indovinare |
| **Cricchetto MCP a 172/168** | Windows, Linux, macOS | **non mio, rimisurato al 612**: dei 172 fabbricatori **zero** hanno prefisso `debug_`/`linux_`/`macos_`/`ios_`/`win_` — sono `il_*`, `pe_editor_*`, `trace_*`, `symb_*`, `sandbox_*` di altri crate. Era 170, ora 172: altri attori ne aggiungono. Da riportare al proprietario, **non** da far tacere alzando il soffitto (lezione 17) |
| **Single step su Windows ARM** | Windows | rifiutato esplicitamente (606): il meccanismo AArch64 non è implementato e inventarlo sarebbe peggio |
| **Watchpoint hw su Windows ARM** | Windows | il CONTEXT ha `Bcr`/`Bvr`/`Wcr`/`Wvr` (**2 slot**, non 4). Capacità dichiarata assente (598) |
| **Eventi di thread** | macOS, iOS | Mach e RSP non li consegnano. Dichiarati assenti col motivo |
| **`task_for_pid` root** | macOS | ⚠️ **decisione dell'utente** |
| **iOS su hardware** | infrastruttura | i runner ospitati non hanno iPhone. Il simulatore però è arm64 REALE |
| **14 file `.bak*`** | `src/` | ⚠️ **decisione dell'utente** |

### 5. Lezioni di metodo

1. **Misurare il rosso PRIMA.** Se passa al primo colpo, **perturbare**.
2. **Ancorare a un IDENTIFICATORE, mai a una stringa** che può stare in un
   commento. Costato quattro volte, incluso un guard soddisfatto dalla propria
   prosa.
3. **Un test può passare A VUOTO** dove i `cfg` lo compilano via.
4. **Un guard deve sorvegliare la POSIZIONE, non la presenza** (607): uno che
   controllasse solo che la maschera PAC esista sarebbe passato per tutto il 591,
   mentre il codice era morto.
5. **Un fallimento indistinguibile da una risposta negativa è taciuto.**
6. **Un flag di contabilità propria non misura il target.**
7. **Correggere una copia su due lascia il difetto.**
8. **Un rifiuto esplicito NON è un difetto**: è una difesa che funziona.
9. **Il difetto sta spesso nella FRASE**, non nel codice.
10. **L'assenza di un fallimento non è la presenza di un successo.** Tre grafie:
    cancelled, tollerato su Linux, tollerato su macOS.
11. **Correggere prima la MISURA, poi il difetto.** Ogni volta che ho reso
    misurabile una piattaforma, quella piattaforma ha detto subito qualcosa che
    nessuno sapeva: la CI Windows non esisteva e ha trovato un backend che non
    compilava; la suite MCP Linux non compilava e ha trovato un cricchetto tarato
    su metà del mondo.
12. **Un ciclo che riprende il target va limitato dagli EVENTI.**
13. **Verificare le PROPRIE dichiarazioni del round precedente**: ha prodotto
    difetti reali otto volte (581, 583, 587, 588, 595, 598, 601, 607).
14. **Chiedere al kernel invece di assumere**: maschera PAC, numero di slot,
    dimensione di pagina, nomi dei campi di `CONTEXT` letti da winapi.
15. **Un file `cfg`-gated non è verificato dalla suite che non lo compila**
    (611): `linux_debugger.rs` è `#[cfg(target_os = "linux")]`, quindi ogni
    «2033/0» su Windows non lo tocca. Il cablaggio del 609 aveva un errore di
    TIPO — una tupla a 2 dove ce n'è una a 3 — e nessun compilatore l'aveva mai
    visto: non Windows (file escluso), non l'harness ARM (estrae un altro
    blocco), non Linux (non c'era stata una run riuscita dopo). **Per un file
    solo-Linux, solo Linux verifica.**
16. **Un fix può essere giusto e MORTO**: sul thread sbagliato (573), dietro
    un'uscita anticipata non correlata (591), dentro un `cfg` mai compilato.
    Verificare che sia stato ESEGUITO, non che sia presente.
16. **Misurare un albero in movimento non è misurare**: `git worktree` e un
    `CARGO_TARGET_DIR` per attore. Usato in cinque round quando altri attori
    avevano rotto la build condivisa.
17. **Non alzare il cricchetto di un altro per farlo tacere**: alzarlo è
    disfarlo. Riportarlo a chi lo possiede.
18. **Una capacità pubblicata in due grafie va accettata in due grafie** (612):
    pubblicarne due e preferirne una fa perdere l'edit di chi usa l'altra. Se non
    si vuole scegliere quale sia canonica, la scelta va spostata al momento della
    scrittura — quella che DIFFERISCE dal registro è la modifica.
19. **Il commento che descrive la difesa va verificato quanto la difesa** (612):
    quello su macOS dichiarava di non far cadere le scritture, ed era vero per
    `x29`/`x30` e falso per il caso simmetrico `fp`/`lr`.
20. **Verificare la propria dichiarazione può anche assolverla** (612): il
    rifiuto del 606 sembrava perdere un handle, ma il contratto lo porta avanti
    e lo chiude al prossimo acknowledge. Nessun difetto — e saperlo vale quanto
    trovarne uno.
21. **Un fallback sui nomi va provato su OGNI nome che accetta** (613): una
    sola riga copriva `ax` e rompeva `eax`, e nessuno dei due casi era testato.
    Il rosso misurato (`None`) non era quello che avevo previsto (64 bit), e ho
    corretto la frase del test, non la misura.
22. **Misurare un albero in movimento non è misurare, di nuovo** (613): la suite
    non compilava per 7 errori in `src/ios/rsp.rs`, riscritto da un agente del
    giro 7 in quel momento. Un `git worktree` su HEAD più i miei due soli file
    ha dato la misura pulita — e ha PROVATO che gli errori non erano miei
    invece di lasciarmelo supporre.
23. **Eseguire TUTTO ciò che il ciclo chiede**: il 605 è emerso perché su Linux
    non stavo eseguendo la suite MCP, solo quella del debugger.


## Stato immediatamente PRIMA della riscrittura del 618

<!-- recuperato da git: 49598406c^ -->

## rustre-debug — stato misurato

> **Regola.** Ogni 4 iterazioni questo file va riscritto DA ZERO. È un cruscotto,
> non un registro. Precedente riscrittura: 608. Questa: **614** — con una
> iterazione di ritardo, annotata invece che nascosta. Aggiornata al **617**.
>
> **Ogni numero è misurato.** «Non dimostrato» = nessuna macchina raggiungibile
> ha risposto: lacuna dichiarata, non dettaglio.

---

### 1. Semaforo

| Dove | Verificato come | Esito |
|---|---|---|
| Windows x86_64 | suite locale, worktree isolato | **2057 / 0** |
| Windows ARM64 | CI `windows-11-arm` | compila (602, 606); non riconfermato dopo il 612 |
| Linux x86_64 | WSL, `--test-threads=1` | **2040 / 0** |
| Linux aarch64 | CI `ubuntu-24.04-arm` | 3 fallimenti al 608; i fix 607/608/609 non ancora rimisurati |
| macOS Intel / Apple Silicon | CI | suite e live test **verdi** |
| Darwin ×2 | `cargo check --target` | **0 errori** |
| iOS Simulator | CI `macos-14`, arm64 reale | **verde** |
| iOS device | CI | compila e **linka** i test; non esegue (serve hardware) |
| MCP | Windows + Linux | **396 / 1** e 367 / 1 |

**Il rosso del debugger è chiuso al 617** (era iOS `encode_into`). Resta l'**1**
dell'MCP, noto e **non mio**, sotto.

### 2. I due rossi aperti, entrambi con proprietario

| Rosso | Prova che non è mio | Chi lo possiede |
|---|---|---|
| `no_new_wire_tool_answers_without_its_required_params` — **172 tool** rispondono senza i parametri che il loro schema dichiara obbligatori, soffitto 168 | dei 172, **zero** hanno prefisso `debug_`/`linux_`/`macos_`/`ios_`/`win_`: sono `il_*`, `pe_editor_*`, `trace_*`, `symb_*`, `sandbox_*`. Era 170 al 605, 172 al 612: sale sotto altri attori | altri crate. **Non** si chiude alzando il soffitto |

### 3. Le tre famiglie di difetti che questo crate produce

1. **Un fallimento riportato come successo**: `let _ =`, `else { continue }`,
   `unwrap_or(0)` che trasforma «non ce l'ho» in zero, un `bool` in cui «non
   trovato» e «non riuscito» collassano, uno step CI `continue-on-error` il cui
   esito non risale, un `Drop` che tace.
2. **Logica condivisa che deriva**: fra i tre backend, fra backend e MCP, fra i
   due lati dello stesso test, fra una capacità DICHIARATA e il codice che la
   nega. Il 612 e il 614 sono entrambi di questa famiglia: **tre copie della
   stessa decisione, con tre risposte diverse**.
3. **Un'assunzione x86 in codice che gira anche su ARM**: byte di trappola,
   allineamento, nomi dei registri, PC al trap, PAC, numero di slot, trap flag.

### 4. Chiuso di recente, con la misura

- **iOS: `fp` e `lr` non arrivavano mai al device** (617). `RegisterMap::encode_into`
  piazzava `GenericRole::Pc` e `Sp` e **non** `Fp` né `Ra`, e non leggeva mai
  `set.fp`/`set.lr`. Poiché `decode` riempie entrambi i campi tipizzati a OGNI
  lettura, un leggi-modifica-riscrivi portava l'edit del chiamante lì dentro;
  `encode_into` ci riscriveva sopra il valore stantio da `set.regs` e lasciava
  `dropped` vuoto, quindi `set_registers` rispondeva `Ok(())` per una scrittura
  che il device non ha mai visto. Su arm64 quelli sono il frame pointer e
  l'indirizzo di ritorno: i due registri con cui si costruisce un backtrace.
  Era rosso da tre round e attribuito con prova a HEAD ogni volta.

- **I nomi di registro stretti funzionano in lettura E in scrittura** (613, 614).
  `eax` non si leggeva affatto (il fallback prependeva `r` e cercava `reax`),
  `ax` restituiva tutti e 64 i bit di `rax`, e scrivere `eax` non faceva
  assolutamente nulla. Decideva il flusso: un breakpoint su `ax == 0x1234` non
  scattava mai col registro a `0x1234`. Ora `register_view` /
  `read_register_by_name` / `write_register_by_name` conoscono la larghezza di
  ogni nome — viste `ah` a bit 8..16, suffissi `r9d`/`r9w`/`r9b`, `w0..w30`
  ARM64, `eip` — e la scrittura stretta **preserva** il resto del registro.
- **Una sola tabella dei sotto-registri, non due** (616). `register_view` (613)
  e `sub_register_of` erano state scritte in parallelo da due attori a poche ore
  di distanza e decodificavano la stessa cosa. Un test differenziale ha chiesto
  loro di **concordare** invece di presumere quale fosse giusta: disaccordo su 5
  nomi — `sil`, `dil`, `bpl`, `spl` ed `eip` — che la seconda non conosceva e
  dichiarava assenti, tutti registri x86-64 veri. Ora `sub_register_of` delega
  (resta pubblica, i suoi chiamanti non cambiano) e il test fallisce se una
  seconda tabella ricompare.
- **Anche la direzione tipizzato→mappa segue il target** (616).
  `sync_map_from_special` sceglieva la grafia con `pc_key(native_arch())`: su
  host x86_64 scriveva `rip` in una mappa che il backend arm64 legge per `pc`,
  quindi `r.pc = new_pc; set_registers(r)` «returns Ok, changes nothing» — che è
  testualmente ciò che la sua doc dichiara di prevenire. Non serviva indovinare:
  il backend ha già pubblicato il vocabolario del TARGET in quella stessa mappa,
  quindi la grafia da usare è quella che c'è già; `native_arch()` resta solo come
  ultima risorsa per una mappa ancora vuota.
- **La vista tipizzata `pc`/`sp`/`fp` segue il TARGET, non il build** (615).
  `RegisterSet::set` teneva in passo `self.pc`/`sp`/`fp` con la mappa — e
  decideva quale nome fosse il program counter chiedendolo a `native_arch()`,
  la cui doc dice essere «l'architettura su cui questo build gira»: l'**host**,
  scelto a compile time. Ogni sessione remota ha un target che è un'altra
  macchina, e una sessione iOS ne ha di routine una di un'altra **architettura**:
  su host x86_64 la funzione cercava `rip` mentre il target pubblica `pc`,
  quindi il campo tipizzato non si aggiornava mai — ed è esattamente il difetto
  che il commento lì sopra dichiarava di aver chiuso, chiuso solo nel caso in cui
  host e target coincidono. `backtrace`, `step_over` e `step_out` leggono quei
  campi «invece della mappa», quindi leggevano un numero stantio e plausibile.
  Ora `is_pc_name`/`is_sp_name`/`is_fp_name_any` iterano su `ALL_STEP_ARCHES`:
  le grafie non collidono fra architetture, quindi non serve sapere quella del
  target — serve smettere di chiedere quella dell'host.
- **Una scrittura a `fp`/`lr`/`x29`/`x30` non viene più scartata** (612). I tre
  backend pubblicavano entrambe le grafie e ne preferivano una diversa ciascuno,
  quindi il normale leggi-modifica-riscrivi perdeva l'edit e riportava successo.
- **Breakpoint software su macOS**: non funzionavano affatto (`mach_vm_protect`
  mancante, 579).
- **Watchpoint dati e breakpoint hardware su ARM64 Linux** (570, 571), `ENOSPC`
  chiuso (589), indirizzo staged conservato (594).
- **macOS riporta l'indirizzo di fault** (595): prima diceva «è crashato» e mai
  «dove».
- **Windows ha una CI** (597) e il backend **compila per ARM64** (602, 606).
- **Sei tool MCP Linux riparati** (605): `linux_debug.rs` non compilava, quindi
  l'intera suite MCP non girava su Linux.
- **iOS, giri avversariali**: giro 6 — 77 agenti, 9 confermati / 9 chiusi / 0
  falsi positivi; giro 7 — 68 agenti, **12 confermati / 12 chiusi**.

### 5. Difetti aperti — dichiarati

| Cosa | Dove | Stato |
|---|---|---|
| **PAC nell'unwinder** | Linux ARM | 573 e 591 erano entrambi codice morto; il 607 lo legge per primo. **Non ancora rimisurato in CI** |
| **2 test sui registri di debug** | Linux ARM | `NT_ARM_HW_WATCH` sembra fallire su quel runner: da capire, non da indovinare |
| **Single step su Windows ARM** | Windows | rifiutato esplicitamente (606): il meccanismo AArch64 non è implementato e inventarlo sarebbe peggio |
| **Watchpoint hw su Windows ARM** | Windows | il CONTEXT ha 2 slot, non 4. Capacità dichiarata assente (598) |
| **Eventi di thread** | macOS, iOS | Mach e RSP non li consegnano. Dichiarati assenti col motivo |
| **`task_for_pid` root** | macOS | ⚠️ **decisione dell'utente** |
| **iOS su hardware** | infrastruttura | i runner ospitati non hanno iPhone. Il simulatore però è arm64 REALE |
| **14 file `.bak*`** | `src/` | ⚠️ **decisione dell'utente** |

### 6. Lezioni di metodo

1. **Misurare il rosso PRIMA.** Se passa al primo colpo, **perturbare**. Un
   rosso da *compilazione* è il tipo debole: dimostra che manca una funzione,
   non che il comportamento fosse sbagliato. Al 614 ho implementato e poi
   perturbato al vecchio comportamento per avere un rosso sul **valore**.
2. **Il rosso misurato smentisce spesso quello previsto** (613): prevedevo «64
   bit», la misura diceva `None`. Si corregge la frase, non la misura.
3. **Ancorare a un IDENTIFICATORE, mai a una stringa** che può stare in un
   commento. Costato quattro volte, incluso un guard soddisfatto dalla propria
   prosa.
4. **Un test può passare A VUOTO** dove i `cfg` lo compilano via.
5. **Un guard deve sorvegliare la POSIZIONE, non la presenza** (607).
6. **Un rifiuto esplicito NON è un difetto**: è una difesa che funziona (606, 601).
7. **Ma un rifiuto può poggiare su una premessa FALSA** (614): un guard rifiutava
   `eip` come «typo per `rip`». Non lo è: è la metà bassa di `rip`, come `eax` di
   `rax`. Ho tolto la premessa falsa e **aggiunto** un'asserzione positiva — il
   guard è più forte, non più debole. Distinguere questo dal caso 601 è il
   giudizio che serve: lì la difesa era stabilita per bisezione contro una
   rottura reale, qui codificava solo un'affermazione sbagliata sui nomi.
8. **Il difetto sta spesso nella FRASE**, non nel codice. Al 612 un commento
   macOS dichiarava di prevenire proprio ciò che non preveniva; al 614 tre
   backend chiamavano «typo» un registro vero.
9. **Correggere una copia su due lascia il difetto** — e al 614 le copie erano
   **tre**, tutte identiche.
10. **Una capacità va corretta in lettura E in scrittura** (613→614): il 613 rese
    `eax` leggibile e lasciò indietro la scrittura. La simmetria è il posto dove
    guardare al round successivo.
11. **L'assenza di un fallimento non è la presenza di un successo.**
12. **Correggere prima la MISURA, poi il difetto.** Ogni volta che ho reso
    misurabile una piattaforma, quella ha detto subito qualcosa che nessuno
    sapeva.
13. **Un ciclo che riprende il target va limitato dagli EVENTI.**
14. **Verificare le PROPRIE dichiarazioni del round precedente**: difetti reali
    nove volte. E al 612 ha **assolto** una dichiarazione, il che vale uguale.
15. **Chiedere al kernel invece di assumere.**
16. **Un file `cfg`-gated non è verificato dalla suite che non lo compila** (611).
17. **Un fix può essere giusto e MORTO**: sul thread sbagliato (573), dietro
    un'uscita anticipata (591), dentro un `cfg` mai compilato.
18. **Misurare un albero in movimento non è misurare** (613, 614): la suite non
    compilava per errori altrui in `src/ios/`. Un `git worktree` su HEAD coi miei
    soli file dà la misura pulita e **prova** di chi sono i rossi. Al 614 quel
    worktree ha dimostrato che un rosso era preesistente eseguendolo a HEAD
    **senza nulla di mio**.
19. **Non alzare il cricchetto di un altro per farlo tacere**: alzarlo è disfarlo.
20. **Eseguire TUTTO ciò che il ciclo chiede**: il 605 è emerso perché su Linux
    non stavo eseguendo la suite MCP, solo quella del debugger.
21. **`native_arch()` risponde all'HOST** (615): usarla per interpretare i nomi
    di registro di un target è corretto solo finché host e target coincidono —
    cioè mai, nel debug remoto. Dove una decisione dipende dall'architettura,
    chiedersi *di chi* è l'architettura è la domanda che rivela il difetto.
22. **Un commento che dichiara di aver chiuso un difetto va riletto sul caso
    generale** (615): quello sopra `RegisterSet::set` descriveva bene il difetto
    e il fix lo chiudeva solo per host == target.
23. **Due implementazioni della stessa decisione: farle CONCORDARE, non
    scegliere a occhio** (616). Il test differenziale non assume che nessuna
    delle due sia giusta: chiede che diano la stessa risposta su ogni nome che
    l'una o l'altra dichiara di gestire. Ha trovato 5 divergenze reali senza che
    servisse alcuna verità esterna — lo stesso principio di `cross_build.py`
    nell'altro crate: se il codice si contraddice, un lato è sbagliato.
24. **Un difetto risolto in una direzione va cercato nell'altra** (615→616):
    mappa→tipizzato e tipizzato→mappa avevano lo STESSO difetto, e la seconda
    metà era rimasta in piedi con la doc che dichiarava di averla chiusa.
25. **Non copiare un FILE intero da un albero condiviso per misurare** (617):
    due volte ho importato in un worktree pulito il lavoro non committato di
    altri insieme al mio — la prima volta un riferimento a una funzione che a
    HEAD non esiste, la seconda un test nuovo il cui codice di produzione non
    avevo copiato. Entrambe le volte il rosso sembrava mio e non lo era.
    Si applica il proprio HUNK sulla versione a HEAD, non si copia il file.
26. **Un mio fix può rendere FALSA la frase di un altro** (617): il 616 ha
    corretto `sync_map_from_special`, e la doc di un guard iOS continuava a
    citarne il difetto come motivo della propria esistenza. Metà del motivo
    regge ancora (`lr` non è previsto lì), metà no: corretta, non cancellata.
27. **Anche il mio contratto va riletto**: al 614 il mio test asseriva `true`
    dove la doc che avevo scritto tre righe sopra prometteva `false`.


## Stato immediatamente PRIMA della riscrittura del 624

<!-- recuperato da git: a894d1ed1^ -->

## rustre-debug — stato misurato

> **Regola.** Ogni 4 iterazioni questo file va riscritto DA ZERO. È un cruscotto,
> non un registro. Precedente riscrittura: 614. Questa: **618**, aggiornata al **623**.
>
> **Ogni numero è misurato.** «Non dimostrato» = nessuna macchina raggiungibile
> ha risposto: lacuna dichiarata, non dettaglio.
>
> Ogni misura è presa in un `git worktree` su HEAD con i **soli hunk miei**
> applicati sopra. L'albero condiviso contiene in permanenza lavoro non
> committato di altri attori e spesso non compila; misurarlo non è misurare.

---

### 1. Semaforo

| Dove | Verificato come | Esito |
|---|---|---|
| Windows x86_64 | worktree isolato, prima del merge | **2062 / 0** |
| Windows x86_64 | dopo il merge col lavoro del giro 9 | **2094 / 1** — il rosso rimasto è iOS, non mio (sotto) |
| Linux x86_64 | WSL, `--test-threads=1` | **2044 / 0** |
| Darwin ×2 | `cargo check --target` | **0 errori** |
| MCP | Windows | **406 / 1** (634) |
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

### 1-bis. ⚠ Un commit altrui ha portato `main` a NON COMPILARE (622)

Il commit `956a6feea` («clippy: five lint classes down») ha incluso, insieme al
proprio lavoro, il **mio 622 a metà** preso dall'albero condiviso: la firma nuova
di `step_off_planted_breakpoint` con i `return None` ancora vecchi, e una
`DebugError::MemoryAccess` che **non esiste**. Verificato: `main` non compilava.
Nei tre backend quel commit non conteneva **nessuna** modifica clippy propria —
ogni riga era mia, trapelata. Ha anche riportato `STATUS.md` al 618, annullando
gli aggiornamenti di 619, 620 e 621.

Il cherry-pick del 622 sopra di esso rimette `main` in compilazione e ripristina
lo STATUS. La causa è il rischio già annotato al 617: **l'albero condiviso non è
uno stage**. Chi committa con `git add` ampio prende il lavoro a metà di tutti
gli altri.

I **2 rossi** che ne sono seguiti non erano miei — **nessuno dei due esiste** in
`944bca0f4`, il mio ultimo verde — ma erano su `main`, quindi al 623 li ho presi
in carico invece di cercare un difetto nuovo. **Uno chiuso**, uno dichiarato con
l'analisi fatta:

- **CHIUSO — `ios::unwind::a_frameless_leaf_with_a_zero_sized_frame_still_has_a_caller`.**
  `validate` rifiutava ogni frame in cui `sp` non **crescesse strettamente**. Ma
  una foglia frameless con stack-size 0 non alloca nulla: l'`sp` del chiamante è
  uguale a quello del chiamato e l'indirizzo di ritorno sta in `lr` — è ciò che
  il compilatore emette per ogni foglia banale, e libunwind fa `sp += stackSize
  * 16` senza pretendere crescita. Qualunque backtrace preso dentro una funzione
  così si fermava a profondità 1, con tutte e tre le strategie che fallivano.
  Ora lo stack non può **calare**, e può restare fermo: lo scopo vero del
  controllo — rifiutare un passo che non fa progresso, così la camminata non
  gira a vuoto — è conservato richiedendo che il pc si muova quando `sp` non lo
  fa, e `backtrace` limita comunque a `max_depth`.
- **APERTO — `ios::apple_debugger::step_out_leaves_the_frame_when_lr_no_longer_holds_the_return_address`.**
  Non è, come sembrava dal messaggio, solo «l'uscita chiamata ritorno»: il test
  pretende che `step_out` **arrivi** al sito di ritorno (`pc == TEXT_BASE+0x0C`),
  e invece il target corre fino all'uscita. Il criterio è `pc == target && sp >=
  min_sp` con `target` letto da `[fp+8]` e `min_sp = fp+16`; una delle due metà
  non si verifica mai in questo scenario. Da guardare lì, non in
  `run_to_return_step`, che su un'uscita reale fa bene a fermarsi. Lasciato al
  giro 9, che sta riscrivendo quel file adesso.

### 2. Le tre famiglie di difetti che questo crate produce

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

### 3. Chiuso di recente, con la misura

- **Uno step fallito non è più «non c'era nessuna trappola»** (622).
  `step_off_planted_breakpoint` ripristina il byte originale, esegue lo step e
  ripianta la trappola; restituiva `Option<DebugEvent>`, e `None` significava
  sette cose — nessun thread corrente, registri illeggibili, breakpoint
  disabilitato, nessun breakpoint piantato, **e lo step stesso fallito**,
  attraverso un `.ok()`. Il chiamante legge `None` come «niente da scavalcare» e
  **rifà lo step**: ma dopo un fallimento la trappola è già stata riarmata e il
  thread non si è mosso, quindi quel secondo step esegue l'`int3`. È parola per
  parola l'esito che la doc di `single_step` indica come la ragione per cui
  questo meccanismo esiste — «the caller asked for one instruction and got none,
  with no error to say so — a debugger that appears stuck». Un guasto transitorio
  veniva convertito nel sintomo esatto.
  Il caso speculare costava un'istruzione invece di perderne una: uno step
  **riuscito** veniva buttato via se il ripiantamento successivo falliva, e il
  chiamante ne faceva un secondo — il thread avanzava di due istruzioni per una
  richiesta. Ora `StepOff` distingue `NotOnATrap` / `Stepped(ev)` / `Failed(e)`,
  e il fallimento del riarmo continua a essere gestito (l'indirizzo smette di
  essere dichiarato piantato) senza più annullare uno step avvenuto.
- **Il rifiuto del 620 non poteva essere disattivato da un refuso** (621).
  `capability_refusal` rispondeva `None` sia per «dichiarata e funzionante» sia
  per «capacità inesistente»: un solo nome sbagliato a un call site —
  `hardware_watchpoint` per `hardware_watchpoints` — avrebbe spento il rifiuto
  per sempre e in silenzio. Un guard il cui modo di fallire è **passare** è
  peggio di nessun guard, perché per giunta gli si crede. Mio, dal 620, trovato
  rileggendolo. Due metà, entrambe necessarie: `capability_status` rende onesta
  la risposta a runtime (`Supported` / `Unsupported(perché)` / `Undeclared`), e
  una scansione del sorgente rende irraggiungibile il caso disonesto —
  controlla ogni letterale passato alla funzione contro i nomi che la
  dichiarazione pubblica, **su tutti i rami `cfg`**, perché questo build vede
  solo il proprio. Il guard ha colto subito un caso vero: era il mio stesso test
  del 620 ad asserire il buco. Perturbato con un refuso realistico in
  produzione: morde.
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

### 4. iOS — giri avversariali

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

### 5. Difetti aperti — dichiarati

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

### 6. Lezioni di metodo

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
23. **Contare quante cose significa un `None`** (622): sette, in una sola
    funzione, e due di esse volevano la gestione opposta. Quando un `Option`
    torna da un'operazione che può sia non applicarsi sia fallire, quelle due
    non possono avere la stessa forma. È il quarto lookup a tre stati che questo
    crate si dà per la stessa ragione.
24. **Un guard che può fallire PASSANDO è peggio di nessun guard** (621), perché
    gli si crede. Ogni lookup che fa da fondamento a un rifiuto deve distinguere
    «non supportato» da «non l'ho trovato», e il nome cercato va verificato
    contro la dichiarazione: altrimenti un refuso è indistinguibile dal via
    libera. Nel crate ci sono ora tre lookup a tre stati per questa ragione —
    `DebugRegisterState`, `CapabilityStatus`, `capability_refusal`.
24. **Il codice che asserisce il difetto va sostituito, non aggirato** (621): il
    mio test del 620 fissava proprio il buco che il 621 chiude, e il guard nuovo
    lo ha additato per primo.
25. **Una capacità DICHIARATA va anche IMPOSTA** (620): la lista era accurata e
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


---

## WORKFLOW #7 — DE-VACUAZIONE 2 — watchpoint e thread/moduli

Bersagli della campagna di falsificazione: `live_linux_watchpoints.rs`
(**1 mordente su 11**) e `live_linux_threads_modules.rs` (**1 su 9**). Nove
guardie nuove in `tests/live_linux_devac_watchpoints.rs`, nessuna delle quali
costruisce l'attesa dal dato che verifica.

### L'oracolo: la DICHIARAZIONE SCRITTA dal tracee

Ogni fixture apre il file passato in `argv[1]` e scrive, PRIMA di fare il
lavoro, gli indirizzi dei propri globali (`%p`), quante volte sta per scriverli
e il `gettid()` di ogni thread che crea. Il debugger non produce nulla di tutto
questo. `OutputRedirect{stdout:true}` non e' implementato da nessun backend
(commento a `lib.rs:2449`), quindi lo stdout vero non e' catturabile: il file e'
lo stdout del programma per altra via, non un ripiego concettuale.
Secondo oracolo indipendente per gli stessi indirizzi: `nm`. Terzo e quarto:
`/proc/<pid>/task` e `/proc/<pid>/maps`, letti dal test.

Contatori (7, 4, 2, 0) tutti DIVERSI: il vettore e' un'impronta
dell'assegnazione indirizzo→nome. Un contatore solo non separa, come gia'
misurato due volte nel giro #6.

### Le sette mutazioni, misurate

| mutazione | rossi su 9 | quali |
|---|---|---|
| `addr_shift` (+8 dall'indirizzo dichiarato) | **2** | conteggi 7,4,2→4,2,0 |
| `swap` (arma w_beta spacciandolo per w_alpha) | **2** | w_alpha riporta 4 invece di 7 |
| `cross` (slot 0 riceve l'indirizzo dello slot 1) | **2** | l'istogramma perde w_alpha |
| `nm_shift` (+0x40 sull'oracolo `nm`) | **1** | i due oracoli divergono |
| `tid_drop` | **2** | insiemi tid |
| `tid_add` (tid 999999 inventato) | **2** | insiemi tid |
| `map_drop` (una mappatura in meno) | **1** | insieme dei path dei moduli |

Ogni guardia e' rossa sotto almeno una mutazione. Pulito: **9/9 verdi, 0 orfani**.

### Tre difetti trovati NEL PROPRIO lavoro, nessuno visibile da un run verde

1. **`swap(0,1)` non incrociava niente.** La prima versione della mutazione
   `cross` scambiava l'ORDINE di armamento: stesso INSIEME di indirizzi,
   istogramma identico, guardia verde. L'incrocio vero e' dare allo slot 0
   l'indirizzo dello slot 1. Misurato: dopo la correzione, 2 rossi.
2. **Il precondizionamento rubava il rosso alla guardia.** `declared.len()==4`
   scattava prima delle comparazioni di insieme, quindi `tid_add` falliva sul
   conteggio e non sull'insieme. Reso `>= 4` — serve solo contro un oracolo
   VUOTO, che sarebbe sottoinsieme di qualunque cosa — e il morso e' tornato
   dove deve stare.
3. **Il test degli orfani non distingueva vivo da zombie.** Un tracee ucciso
   sul percorso di panic resta visibile a `pgrep` finche' il tracer non lo
   raccoglie, e il tracer e' un thread di QUESTO binario. Ora lo stato viene
   letto da `/proc/<pid>/stat`: zombie stampato, vivo = rosso.

### ROSSO MISURATO nel backend: un panic puo' APPENDERE il test successivo

Sotto `tid_add`, le due guardie thread sono andate in panic e la `start()`
successiva e' rimasta appesa **18 minuti** in `futex_do_wait` con la fixture che
girava (`ps`: `6547 Rl+ devacthr`). Causa nota e gia' documentata in
`live_linux_threads_modules.rs`: il loop del debugger reap-a con
`waitpid(-1, __WALL)`, che e' GLOBALE al processo, e un `LinuxDebugger` di un
test morto continua a mangiarsi gli stop del figlio successivo. Non corretto nel
backend (fuori mandato): il test ora avvolge `launch` in un timeout di 30 s e
spazza la fixture stantia, cosi' l'attesa infinita diventa un fallimento
leggibile. Dopo la cura: `tid_add` chiude in **2,95 s**, `tid_drop` in **1,46 s**,
zero orfani.

### Nota di metodo

Due file assegnati erano gia' in modifica da altri agenti (`mtime` di
`live_linux_threads_modules.rs` a 3 minuti prima dell'inizio): tutto il lavoro
sta nel file nuovo, nessuno dei due e' stato toccato.

## Giro 653 — un watchpoint era elencato ma non indirizzabile

**Difetto (gap 4 dell'audit x64dbg).** `debug.breakpoints` elenca anche i
watchpoint, ma reversa SOLO la mappa `addr_to_id` dei breakpoint software:
per un watchpoint la ricerca fallisce e la riga esce con `breakpoint_id: null`.
Lo stesso watchpoint, chiesto a `debug.watchpoints`, ha un id valido `wp_1`.
Era quindi **visibile ma non azionabile** dalla lista unificata: il chiamante lo
vede e non ha nulla da passare a un tool successivo.

**Rosso misurato PRIMA della cura**, guard `the_unified_breakpoint_listing_names_every_row`:
> the unified listing reverses only `bp_ids`, so a watchpoint is listed with a
> null id and cannot be acted on from there

**Cura.** La riga ora ricade su `sess.watchpoints.all()` e riporta `wp_N`.
Scelta deliberata: ogni id resta nella forma a cui risponde il SUO tool
(`bp_N` / `wp_N`), così il chiamante impara anche quale chiamata fare dopo,
invece di ricevere un id ambiguo che una sola delle due famiglie accetta.

### Il guard ha mentito, e questo e' il risultato piu' utile del giro

La prima versione dell'ancora cercava `watchpoints.all()` come stringa
contigua. Ma la cura e' scritta su due righe (`sess.watchpoints` a capo
`.all()`), quindi quella stringa **li' non esiste**: il guard ha proseguito e ha
trovato la copia del tool `debug.watchpoints`, a **34874 caratteri** di distanza,
riportando un fallimento riferito a codice che non avevo toccato.

Non era un rosso rumoroso: era un rosso **plausibile**, con un messaggio
sensato su codice reale, che diceva il falso. Se lo avessi creduto avrei
riscritto qualcosa di gia' corretto — lo stesso schema del giro 650, dove un
guard ancorato a una finestra di byte fu riancorato a `fn enrich_frame(`.

Riancorato a `sess.watchpoints`, che la formattazione non puo' spezzare, e
falsificato su quattro punti: ancora nuova presente nella finestra, ancora
vecchia ASSENTE (che e' la prova della diagnosi), manomissione -> rosso,
finestra corretta (contiene `addr_to_id`). Il commento nel codice registra che
quel guard ha gia' mentito una volta, e perche'.

**Regola aggiunta:** un guard testuale non deve mai ancorarsi a una stringa che
la formattazione del codice puo' spezzare su piu' righe. Se lo fa, non fallisce:
trova il prossimo simile e accusa l'oggetto sbagliato.

### Suite del giro 653

- **MCP**: 411 passati, 1 fallito. L'unico rosso e' il cricchetto FABRICATOR
  preesistente (175 su 2390), che non e' mio, non contiene alcun tool `debug.*`
  e NON va chiuso alzando il tetto. Il guard nuovo risulta `ok`.
- **Windows**: 2129 passati, 0 falliti.
- **Darwin** x86_64 e aarch64: entrambi `Finished`, zero errori. Restano due
  `unused import` sul percorso Apple, che e' sospeso: la regola vieta di
  zittirli con `#[allow]` e cablarli sarebbe sviluppo iOS, quindi restano.
- **Linux**: NON conclusa — si e' bloccata. Vedi il giro 654: non e' una
  regressione di questo giro, e' un difetto preesistente che questa esecuzione
  ha finalmente colto in flagrante.

---

## Giro 654 — DEADLOCK a tre vie nel backend Linux, letto dal kernel

Il difetto piu' grave trovato oggi, e non e' stato dedotto: e' stato **letto in
diretta** da `/proc` mentre la suite era ferma.

**Sintomo.** `cargo test -p rustre-debug --lib` sotto WSL non termina. Il segnale
che distingue «lento» da «bloccato» e' il tempo di CPU: **347 secondi di orologio
contro `00:00:00` di CPU**. Non stava lavorando piano, non stava lavorando.

**Le tre parti, ognuna verificata:**

| pid/tid | chi e' | stato | dove |
|---|---|---|---|
| 7678 | il worker del tracee | **`t`** | `ptrace_stop` — mai ripreso |
| 7677 | il main del tracee | `S` | `futex_do_wait`, dentro `pthread_join` |
| 7676 | thread `linux_debugger:` (Tgid 6260) | `S` | `do_wait`, cioe' `waitpid` |

**Causa, in una frase:** `continue_execution` riprende il thread che ha riportato
lo stop ma lascia il thread APPENA NATO fermo nel suo birth-stop. Il main del
tracee lo aspetta in `pthread_join` e non arrivera' mai al suo `raise(SIGTRAP)`;
il debugger aspetta in `waitpid` un evento che nessuno puo' piu' produrre.
Ognuno dei tre aspetta uno degli altri due.

E' esattamente il modo di fallire che i commenti di `linux_debugger.rs`
descrivono gia' («an event handed to the caller for a thread that nobody
resumed, which is how this backend hung before»): la diagnosi era scritta nel
file, il caso non era chiuso.

**Test colpito:** `a_threads_birth_and_death_both_reach_the_caller`, che usa
`DYING_THREAD_FIXTURE_C` (pthread_create -> pthread_join -> raise(SIGTRAP)).
Il suo ciclo e' limitato a 64 giri, quindi il blocco NON e' nel test: e' dentro
una singola `continue_execution().await`.

**Non e' una regressione del giro 653.** `linux_debugger.rs` non e' toccato dalle
11:48 e la modifica del 653 e' in `rustre-mcp-tools`. Il workflow #7 lavora solo
in `tests/`, per regola. La suite Linux era passata prima (2080/0): il difetto e'
sensibile all'ordine degli eventi e si manifesta sotto carico, che e' il motivo
per cui e' sopravvissuto a piu' giri verdi.

**Due cure distinte, da non confondere:**
1. la vera: riprendere OGNI thread fermo, non solo quello che ha riportato lo
   stop;
2. la difensiva: dare un timeout a questo test, perche' un blocco diventi un
   ROSSO con diagnosi invece di fermare l'intera suite per sempre — che e' la
   regola che il file stesso enuncia e che questo test viola.

---

## Workflow #7 (`wf_70b2361c-8eb`) — 5 agenti su 5, e una SMENTITA

Secondo giro di de-vacuazione + **verifica indipendente** dei due file gia'
corretti. La verifica e' la parte che conta, perche' ha demolito una
dichiarazione precedente.

### La smentita, e perche' e' istruttiva

Il giro precedente aveva dichiarato `live_linux_breakpoints.rs` mordente
**20/21**. Misurato di nuovo con una mutazione COERENTE (a `hot` si da'
l'indirizzo di `warm` **e** la finestra objdump di `warm`): morde **6/21** —
`15 passed; 6 failed`.

Il 20/21 era riproducibile solo lasciando i due oracoli **discordi**: in quel
caso `assert_address_is_hot` falliva perche' `nm` non concordava con `objdump`,
non perche' l'indirizzo fosse sbagliato. **La finestra di 32 byte coglieva il
disaccordo fra oracoli, non la funzione sbagliata.** La capacita' era reale, la
frase piu' forte della misura — la stessa classe di errore che ho gia' commesso
io al giro 648 su `parse_elf`.

I 6 che mordono davvero sono tutti sui **conteggi di attraversamento**, nessuno
sulla finestra di byte: conferma diretta della regola «un conteggio e' lasco, una
TRIPLA no» — qui (5,1,0) per (hot, warm, cold).

### Difetti nuovi, ciascuno col rosso misurato

1. **Nessun oracolo fissa l'ENTRY.** `hot + 8` e' dentro `hot`, su confine
   d'istruzione, attraversato le stesse 5 volte: con la finestra traslata la
   suite resta **21 passed / 0 failed**. Chiuso da un guard nuovo che confronta
   con l'entry pubblicata E aggiunge la meta' negativa (i byte a `hot+8` NON
   devono coincidere con quelli dell'entry).
2. **`pin_addresses` fissa una FUNZIONE, non un indirizzo**: con `filler+128`
   stampa `measured` identico ad `expected` e passa. Morso reale **0/9**.
3. **`a_thread_storm_does_not_disarm_the_planted_breakpoints` puo' passare senza
   controllare nulla**: le sue due asserzioni vere stanno dentro `if alive`.
   Stessa mutazione, due corse diverse: `8 passed; 1 failed` poi `7 passed; 2
   failed`; isolato fallisce sempre. **Il salto non era registrato da nulla** —
   un test che si autoesenta in silenzio.
4. Soglia lasca residua nello stesso test: `traps >= addrs.len() - 1` mentre
   l'altro storm e' stato irrigidito a `== n`.

### Vacuita' dichiarate LEGITTIME (non tutto cio' che non morde e' un difetto)

`0xCC->0xCD` morde 4/21 e 2/9, ed e' corretto: solo quei test affermano qualcosa
sul valore del byte. `hot+8` per i test di piantatura/ripristino resta legittimo:
l'affermazione «una trappola si pianta e si ripristina dentro `hot`» e' vera; e'
la DOC a promettere l'entry, per questo il guard e' un'aggiunta e non una
correzione.

### L'agente ha falsificato il PROPRIO oracolo, ed e' andato rosso

Primo tentativo: aveva scambiato i **corpi** oltre ai nomi, e i due programmi
stampavano entrambi `7` — `left "7" right "11"`. L'oracolo non separava nulla.
Corretto scambiando i **siti di chiamata** e lasciando i corpi: `fixture=7
swapped=11`. **Lo stdout del programma e' l'unico oracolo del crate che
sopravvive a una mutazione del PROGRAMMA**, e nessuno dei due file de-vacuati lo
usava.

### Il ramo fork/segnali

`OutputRedirect::stdout` e' documentato come non implementato da nessun backend,
quindi lo stdout del tracee non e' leggibile ATTRAVERSO la crate. L'agente ha
aggirato l'ostacolo senza fingere: le fixture scrivono con `open`/`write` (non
`stdio`, perche' uno degli scrittori e' un handler di segnale) su un log il cui
path arriva da `argv`. 7 test su 8 mordono; l'ottavo e' vacuo e **dichiarato
tale**: asserisce solo che nessun processo fixture sopravvive.

### File prodotti (nessun file di produzione toccato, per regola)

`tests/live_linux_devac_audit.rs` (4 attivi + 1 `#[ignore]` che asserisce un
difetto misurato), `tests/live_linux_devac_fork_signals.rs` (8 test).
I file altrui sono stati ripristinati e verificati `cmp`-identici; suite finali
21/0 e 9/0; `pgrep -x` su tutti gli stem: zero orfani.

### Giro 654 — la cura

**Fail-first misurato PRIMA di toccare il codice**, contando i punti invece di
fidarmi dell'impressione: dei **3 `PTRACE_CONT` in produzione, 2 buttavano via
l'esito** — righe 2077 (il genitore dopo l'evento di clone) e 2089 (il nuovo nato
al suo birth-stop). L'unico controllato era quello del Continue. Sono
esattamente i due che RIPRENDONO un thread: se falliscono, quel thread resta in
ptrace-stop per sempre e nessuno lo viene a sapere.

**Tre modifiche, in `src/linux_debugger.rs`:**
1. i due esiti ora sono controllati; se la ripresa fallisce il tid **resta** in
   `stopped_tids` invece di essere perso;
2. `stopped_tids` diventa coerente: il ramo del clone lo aggiornava, quello
   della nascita no — due meta' dello stesso fatto che si contraddicevano;
3. **lo sweep**: «continue» significa continuare il PROCESSO, quindi il Continue
   riprende ogni thread ancora fermo, non solo l'ultimo che ha riportato lo
   stop. `stopped_tids` era mantenuto da sempre e **mai consultato li'**:
   capacita' presente e spenta, non assente.

**Guard nuovo** `no_ptrace_cont_discards_its_result` in `lib.rs`. E' un guard sul
SORGENTE per una ragione precisa: riprodurre il deadlock significa scrivere un
test che SI BLOCCA quando il codice e' sbagliato, e questo crate ha gia' imparato
(giro 526) che un test che si blocca non prova nulla e avvelena le corse
successive.

**Il guard ha sbagliato due volte prima di funzionare, e le due volte contano:**
- prima versione: accusava ogni riga che inizia con `libc::ptrace(` — cioe'
  TUTTE, curate o no, perche' la chiamata sta su riga propria dentro
  `let ok = unsafe { .. }`. Sarebbero stati **falsi positivi al 100%**, contro il
  codice che risolve il difetto;
- seconda versione: guardava se le righe sopra legano il risultato, ma la riga
  di traccia soprastante e' `eprintln!("... status={status:#x} ...")` e quell'`=`
  dentro la stringa le faceva **mancare del tutto** il sito 2077.
- terza: toglie i letterali prima di guardare. **Falsificato in entrambe le
  direzioni contro il sorgente pre-cura preso da git: 2 accusati prima
  (2077, 2089 — gli stessi due contati a mano), 0 dopo.**

**Suite del giro 654:**
- **Linux**: `2109 passed; 0 failed`, e soprattutto
  `a_threads_birth_and_death_both_reach_the_caller ... ok` — il test che era in
  deadlock — con la suite chiusa in 3,19 s invece che bloccata.
- **Windows**: `2130 passed; 0 failed` (2129 + il guard nuovo).
- **MCP**: 411 passati, 1 fallito: identico a prima, il solito cricchetto
  FABRICATOR preesistente. Nessuna regressione.
- **Darwin** x86_64 e aarch64: entrambi `Finished`, zero errori.

**Onesta' sulla forza della prova.** Il verde di Linux NON dimostra da solo che
il deadlock sia chiuso: quella suite era verde anche prima, perche' il difetto
dipende dall'ordine degli eventi. Cio' che regge sono due cose diverse: la causa
letta dal kernel (tre stati incompatibili fra loro) e il guard sulla FORMA del
codice, che non dipende dall'ordine di esecuzione. Il test verde e' il terzo
indizio, non il primo.

**`rustre-mcp-tools/tools/debug.rs` NON e' stato toccato**, e la regola non e'
stata dimenticata: questa modifica cambia la semantica interna della ripresa, non
la superficie dell'API — nessun tool cambia forma, tipo o risposta. Due volte in
due giri ho lasciato che i due strati si contraddicessero; qui non c'e' nulla da
propagare.

**Nota di metodo, gia' costata una compilazione:** `linux_debugger.rs` e'
`cfg(target_os = "linux")`, quindi **la suite Windows non puo' vedere un errore
li' dentro**. Il mio `trace` fuori scope e' passato indenne dal verde di Windows
ed e' stato colto solo da WSL. Un file per piattaforma e' verificato da UNA
piattaforma sola.
