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
| MCP | Windows | **405 / 1** (632) |
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
