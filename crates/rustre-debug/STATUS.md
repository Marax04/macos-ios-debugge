# rustre-debug — stato misurato

> **Regola di questo file.** Ogni 4 iterazioni va riscritto DA ZERO. È un
> cruscotto, non un registro: se cresce per stratificazione smette di rispondere
> alla domanda per cui esiste — *a che punto siamo davvero?*
> Riscrittura precedente: 581. Questa: **590**.
>
> **Ogni numero è misurato.** «Non dimostrato» significa che nessuna macchina
> raggiungibile ha risposto: è una lacuna dichiarata, non un dettaglio.

---

## 1. Semaforo

| Dove | Come è verificato | Esito |
|---|---|---|
| Windows x86_64 | suite locale | **2019 / 0** |
| Linux x86_64 | WSL, `--test-threads=1` | **2002 / 0** |
| Linux aarch64 | CI `ubuntu-24.04-arm` | **1993 / 6** su `3e3b5bf` — 5 dei 6 hanno UNA causa, chiusa al 589 |
| macOS Intel | CI `macos-15-intel` | **verde, live test inclusi** ✅ |
| macOS Apple Silicon | CI `macos-14` | **verde, live test inclusi** ✅ |
| iOS Simulator | CI | 1930 / 1 su `d1948ad` — causa mia, chiusa al 588 |
| iOS device | CI | **compila soltanto**, nessun test: serve runner self-hosted |
| MCP | suite locale | **392 / 0** |
| Darwin ×2 | `cargo check` | 0 errori |
| Codice ARM64 Linux | harness `libc`-only, target reale | type-check ✅ |

**Il verde di un job non è il verde di una riga, e il verde di una riga non è il
verde dei suoi test.** Su questo repo si leggono i LOG.

## 2. Il traguardo raggiunto in questa sessione

**I breakpoint software su macOS ora funzionano.** Non funzionavano affatto —
`mach_vm_write` nel `__TEXT` falliva con `KERN_INVALID_ADDRESS` a ogni tentativo
perché nessuno alzava la protezione della pagina (579). Le righe macOS Intel e
Apple Silicon sono ora verdi **live test inclusi**, confermato dai log.

Su ARM64 Linux esistono ora watchpoint dati (570) e breakpoint hardware (571)
dove prima c'era un rifiuto.

## 3. Le tre famiglie di difetti che questo crate produce

1. **Un fallimento riportato come successo.** `Ok(())` letterale, `let _ =`,
   `else { continue }`, un `bool` in cui «non trovato» e «non riuscito»
   collassano, uno step CI `continue-on-error` il cui esito non risale, una
   scrittura dimensionata male che riesce senza armare nulla.
2. **Logica condivisa che deriva.** Fra i tre backend, fra backend e MCP, e fra
   due lati dello stesso test: la CI segnalava 2 usi di `rip`, i siti erano 4;
   un test aveva il lato «salva» architetturale e il lato «asserisci» x86.
3. **Un'assunzione x86 in codice che gira anche su ARM.** Byte di trappola,
   allineamento, nomi dei registri, PC al trap, PAC, numero di slot di debug.

## 4. Difetti aperti — dichiarati, non nascosti

| Cosa | Dove | Stato |
|---|---|---|
| **PAC nell'unwinder** | Linux ARM | **ancora rosso** dopo il 573: o il kernel non risponde a `NT_ARM_PAC_MASK` su quel runner, o lo strip non raggiunge quel percorso. Non indovinato |
| **`ENOSPC` sui registri di debug** | Linux ARM | chiuso al 589, **non ancora dimostrato**: risponde il run su `193c7c0` |
| **`pthread_create` espone 1 thread** | Linux ARM | non più fra i rossi dopo il 587; da riconfermare |
| **Eventi di thread** | macOS, iOS | Mach e RSP non li consegnano. Pubblicato come capacità ASSENTE con il motivo (577, 588), non simulato |
| **Indirizzo faultante** | macOS | `__far` non esposto da `mach2`; un offset sbagliato darebbe un indirizzo plausibile e falso |
| **`task_for_pid` richiede root** | macOS | vincolo di piattaforma. ⚠️ **decisione dell'utente** |
| **`continue-on-error`** | CI Linux + macOS | da togliere quando le righe sono verdi, non prima |
| **Canonico del frame pointer** | crate | `x29` vs `fp`: pubblicati entrambi per non decidere di nascosto. ⚠️ **decisione dell'utente** |
| **iOS su hardware** | infrastruttura | non ottenibile su Actions |
| **14 file `.bak*`** | `src/` | ⚠️ **decisione dell'utente** |

## 4-quinquies. 595-597 — una capacità dichiarata falsa, e la CI che mancava

**595 — macOS PUÒ riportare l'indirizzo di fault, e io avevo scritto di no.**
Il 577 pubblicava `fault_address: supported: false` motivando che *«verrebbe da
`__far` via `thread_get_state`, che `mach2` non espone»*. La premessa è vera, la
conclusione no: questo backend **dichiara già a mano** ciò che `mach2` omette —
`ArmDebugState64` è lì per quel motivo, con size-assert a compile time. La
capacità era raggiungibile col pattern del file stesso.

Una dichiarazione falsa in `backend_capabilities()` è peggio di una funzione non
implementata: quella lista esiste perché un chiamante possa fidarsi. Prima macOS
rispondeva «è crashato» e mai «dove».

**596 — il job iOS device ora LINKA i binari di test.** I runner ospitati non
hanno iPhone fisici, e nessuno ne ha: solo un self-hosted con device via USB
esegue `aarch64-apple-ios`. Ora è scritto nel workflow perché nessuno ci perda un
giro. Ma `cargo test --no-run` compila E linka tutti i test per il device —
tutto tranne l'esecuzione. Da registrare: il simulatore gira su `macos-14`
(Apple Silicon) con `aarch64-apple-ios-sim`, quindi quei 1930 test eseguono
**codice arm64 iOS reale** contro il `debugserver` di Apple. Non è un mock.

**597 — Windows non aveva NESSUNA CI.** Misurato: `.github/workflows/` conteneva
solo Linux e macOS. È lo stesso buco che `linux-debugger.yml` fu creato per
chiudere, ed è più facile da non vedere proprio perché Windows è la macchina di
sviluppo: ogni verde che ha mai riportato viene da un host solo.

La riga ARM64 è quella mai misurata. `windows_debugger.rs` rifiuta ancora i
watchpoint hardware fuori da x86 mentre Linux (570) e macOS traducono, e
Windows-on-ARM ha `Bcr`/`Bvr`/`Wcr`/`Wvr` nel suo CONTEXT — quindi la capacità è
raggiungibile lì come altrove. **Non implementata di proposito**: il 569 lifted
una difesa su una previsione e andò corretto; la regola che ne è uscita è che si
rimuove quando una macchina può rispondere. Questo workflow è quella macchina.

Misurato mentre lo scrivevo: `cargo check --target aarch64-pc-windows-msvc` non
gira sull'host di sviluppo — `libsqlite3-sys` vuole un cross-compiler C, lo
stesso muro di `aarch64-unknown-linux-gnu`. Non c'è surrogato locale.

### 598 — la stessa dichiarazione falsa, sull'altro backend

Trovata misurando le asimmetrie fra i tre backend, non leggendo a caso: Windows
è l'unico che ancora rifiuta i watchpoint hardware fuori da x86 — Linux li
traduce via `NT_ARM_HW_WATCH` (570), macOS via `ARM_DEBUG_STATE64`. Ma
`backend_capabilities()` dichiarava `hardware_watchpoints: true` **senza gate**,
quindi su Windows-on-ARM l'API promette ciò che la chiamata dopo rifiuta.

Stessa classe del `fault_address` macOS corretto al 595, e **le ho introdotte
entrambe nel 577**. Ora la dichiarazione usa lo stesso `cfg!` del backend, così
le due non possono divergere per costruzione invece che per memoria.

Il guard che le tiene allineate **passa a vuoto su questo host** (qui x86 e
dichiarazione concordano): il difetto vive dove non posso compilare. Perturbato
per dimostrare che non è inerte — dichiarando `false` su x86 diventa rosso col
messaggio giusto. La riga `windows-11-arm` del 597 è ciò che lo verificherà dove
conta.

## 4-ter. Il primo run ARM che risponde davvero (593-594)

`193c7c0` ha chiuso l'`ENOSPC`: **1993/6 → 1997/5**, e nessun «No space left on
device». I test ora superano la scrittura e falliscono più a valle, che è
progresso vero e non spostamento del problema.

| difetto | round |
|---|---|
| `ah` e `eax` cablati x86 — 575 aveva migrato solo `al`, **terza** mezza migrazione nello stesso test | 593 |
| un indirizzo messo in `DR0` senza abilitarlo spariva alla rilettura | 594 |

Il 594 è il più interessante. Su x86 si può mettere un indirizzo in `DR0` e
abilitarlo dopo in `DR7`: il registro indirizzo è indipendente dal bit di
enable. La mia traduzione azzerava lo slot disabilitato, quindi **una scrittura
riuscita restituiva un valore svanito**. AArch64 esprime esattamente lo stesso
stato — `DBGWVR` con l'indirizzo, `DBGWCR` con `E=0` — quindi ora l'indirizzo si
conserva e il controllo resta azzerato: niente è armato, e ciò che il chiamante
ha scritto si rilegge.

Sul 593 la sfumatura decide il fix: `ah` **non è una lacuna del backend**, è un
registro che su AArch64 non esiste. Quindi non si salta il test: su x86 si
asserisce che le tre grafie derivino dal registro vivo, su ARM che i nomi x86
siano RIFIUTATI invece che inventati.

## 4-quater. Workflow iOS, giro 4

66 agenti, **4 difetti confermati e 4 chiusi, 0 falsi**. Tutti della famiglia
«risposta inventata»: un offset ivar non risolto riportato come `0` (che è lo
slot dell'isa, un valore legittimo e sbagliato), un `E.` di errore RSP trattato
come payload valido, una reply `p` troncata restituita come `Ok(0)`.

## 4-bis. Un difetto reso impossibile da reintrodurre (592)

`ptrace` è valido SOLO dal thread che ha fatto l'attach — regola già scritta in
`linux_debugger.rs` per `PTRACE_POKEUSER`, e violata comunque per diciotto round
(il 573, scoperto al 591). Da un thread qualsiasi risponde ESRCH: il codice
compila, gira, ed è **silenziosamente un no-op** solo sull'architettura che
nessuno può eseguire in locale.

Nessun compilatore e nessun test x86 può coglierlo, quindi ora c'è un guard che
lo vieta a livello di sorgente. Perturbato per dimostrare che sa fallire:
reintroducendo il difetto nomina la funzione e l'helper esatti.

**Il guard ha trovato subito un secondo caso — che era un FALSO POSITIVO suo.**
Cercava `byte_at(` e lo trovava dentro un commento (*«This used to be spelled
inline as `byte_at(pid, rip - 1)`»*): la lezione 2 violata proprio dal guard che
la applica. Ora i commenti vengono rimossi prima dell'analisi.

## 5. Lezioni di metodo

1. **Misurare il rosso PRIMA del fix.** Un test che passa senza aver mai fallito
   non dimostra nulla. Un test che passa al primo colpo va **perturbato**.
2. **Ancorare un guard a un IDENTIFICATORE, mai a una stringa.** Costato tre
   volte: verde a vuoto, rosso falso, e un guard soddisfatto da un commento.
3. **Un test può passare A VUOTO**: blocchi `cfg` compilati via su una
   piattaforma. Misurare il rosso dove l'asserzione ha senso.
4. **Un fallimento indistinguibile da una risposta negativa è taciuto.**
5. **Preferire un fix verificativo a uno additivo**: chiedere allo stato reale
   «cosa manca?» copre anche i percorsi non enumerati.
6. **Un flag di contabilità propria non misura il target.** Per ogni campo
   pubblicato: *misura il target o misura noi?*
7. **Risalire la catena prima di dichiarare chiuso**: un fix a metà catena vale
   zero se il chiamante butta via il risultato.
8. **Correggere una copia su due lascia il difetto** — fra backend, fra livelli,
   e fra i due lati di uno stesso test.
9. **Cosa c'è dietro il nome che sto per cambiare?** Una difesa che sembra
   obsoleta può essere viva; una che sembra viva può essere obsoleta; un rifiuto
   esplicito NON è un difetto.
10. **La cautela su una premessa non verificata non è cautela.**
11. **Il difetto sta spesso nella FRASE**, non nel codice: portata dichiarata
    troppo larga, previsione scritta al presente, nota `SAFETY` falsa, parametro
    documentato e mai letto, un nome per due significati.
12. **L'assenza di un fallimento non è la presenza di un successo.** Tre grafie:
    *cancelled non è failure*, *un fallimento tollerato non è un fallimento* su
    Linux e su macOS.
13. **Correggere prima la MISURA, poi il difetto.** Su entrambe le piattaforme il
    difetto grave è emerso solo dopo aver reso visibile il fallimento.
14. **Non far passare un test nel modo più rapido**: non sintetizzare un evento
    più debole di quello vero, non inventare un valore magico per una
    piattaforma sola, non ammorbidire una difesa corretta.
15. **Un ciclo che riprende il target va limitato dagli EVENTI, non da una
    condizione sullo stato.** Un limite sui TENTATIVI non è un limite sul TEMPO:
    `continue_execution()` blocca finché non arriva il prossimo stop. Costato 87
    minuti di CI e due misurazioni non correlate.
16. **Un job ucciso dal proprio timeout cancella il segnale di ogni altro test**
    al suo interno. Alzare il tetto è la reazione istintiva e quasi sempre
    quella che nasconde il problema.
17. **Verificare le PROPRIE dichiarazioni del round precedente.** Ha prodotto
    difetti reali quattro volte: 581, 583, 587, 588.
18. **Chiedere al kernel invece di assumere.** La maschera PAC, il numero di
    slot di debug, la dimensione di pagina: ogni volta che ho cablato una
    costante «ovvia» era sbagliata su una delle due architetture.
