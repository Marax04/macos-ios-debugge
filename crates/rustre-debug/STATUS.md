# rustre-debug — stato misurato

> **Regola.** Ogni 4 iterazioni questo file va riscritto DA ZERO. È un cruscotto,
> non un registro. Precedente riscrittura: 608. Questa: **614** — con una
> iterazione di ritardo, annotata invece che nascosta. Aggiornata al **616**.
>
> **Ogni numero è misurato.** «Non dimostrato» = nessuna macchina raggiungibile
> ha risposto: lacuna dichiarata, non dettaglio.

---

## 1. Semaforo

| Dove | Verificato come | Esito |
|---|---|---|
| Windows x86_64 | suite locale, worktree isolato | **2056 / 1** |
| Windows ARM64 | CI `windows-11-arm` | compila (602, 606); non riconfermato dopo il 612 |
| Linux x86_64 | WSL, `--test-threads=1` | **2039 / 1** |
| Linux aarch64 | CI `ubuntu-24.04-arm` | 3 fallimenti al 608; i fix 607/608/609 non ancora rimisurati |
| macOS Intel / Apple Silicon | CI | suite e live test **verdi** |
| Darwin ×2 | `cargo check --target` | **0 errori** |
| iOS Simulator | CI `macos-14`, arm64 reale | **verde** |
| iOS device | CI | compila e **linka** i test; non esegue (serve hardware) |
| MCP | Windows + Linux | **396 / 1** e 367 / 1 |

L'**1** del debugger e l'**1** dell'MCP sono due rossi noti e **non miei**, sotto.

## 2. I due rossi aperti, entrambi con proprietario

| Rosso | Prova che non è mio | Chi lo possiede |
|---|---|---|
| `the_ios_backend_encodes_the_typed_fp_and_lr_fields` — `encode_into` non scrive `GenericRole::Fp`, quindi il campo tipizzato cade in scrittura e `set_registers` risponde `Ok(())` lo stesso | eseguito su un worktree a HEAD **senza nessuna mia modifica**: fallisce identico. Fallisce su Windows E su Linux, quindi non dipende dal target | lavoro iOS; il giro 7 lo ha già preso in carico |
| `no_new_wire_tool_answers_without_its_required_params` — **172 tool** rispondono senza i parametri che il loro schema dichiara obbligatori, soffitto 168 | dei 172, **zero** hanno prefisso `debug_`/`linux_`/`macos_`/`ios_`/`win_`: sono `il_*`, `pe_editor_*`, `trace_*`, `symb_*`, `sandbox_*`. Era 170 al 605, 172 al 612: sale sotto altri attori | altri crate. **Non** si chiude alzando il soffitto |

## 3. Le tre famiglie di difetti che questo crate produce

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

## 4. Chiuso di recente, con la misura

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

## 5. Difetti aperti — dichiarati

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

## 6. Lezioni di metodo

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
25. **Anche il mio contratto va riletto**: al 614 il mio test asseriva `true`
    dove la doc che avevo scritto tre righe sopra prometteva `false`.
