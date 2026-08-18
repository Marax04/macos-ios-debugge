# rustre-debug — stato misurato

> **Regola di questo file.** Ogni 4 iterazioni va riscritto DA ZERO. È un
> cruscotto, non un registro. Riscrittura precedente: 590 — poi ne ho appese
> quattro sezioni in coda, che è la stratificazione che la regola vieta, quindi
> questa era in ritardo di sei round. Questa: **601**.
>
> **Ogni numero è misurato.** «Non dimostrato» = nessuna macchina raggiungibile
> ha risposto: lacuna dichiarata, non dettaglio.

---

## 1. Semaforo

| Dove | Come è verificato | Esito |
|---|---|---|
| Windows x86_64 | suite locale | **2027 / 0** |
| Linux x86_64 | WSL, `--test-threads=1` | **2008 / 0** (al 596) |
| Linux aarch64 | CI `ubuntu-24.04-arm` | **1997 / 5** su `193c7c0` — `ENOSPC` chiuso, 590/591/594 non ancora misurati |
| macOS Intel | CI `macos-15-intel` | **verde, live test inclusi** ✅ |
| macOS Apple Silicon | CI `macos-14` | **verde, live test inclusi** ✅ |
| iOS Simulator | CI `macos-14`, arm64 reale | **1930 / 1** → causa mia, chiusa al 588 |
| iOS device | CI | compila e ora **linka i test**; non esegue (serve hardware) |
| Windows ARM64 | CI `windows-11-arm` | **mai misurato** — riga creata al 597, primo run in corso |
| MCP | suite locale | 392/0 fino al 594; **1 rosso non mio** (cricchetto `wire_tools`) |
| Darwin ×2 | `cargo check` | 0 errori |
| Codice ARM64 Linux | harness `libc`-only sul target reale | type-check ✅ |

**Il verde di un job non è il verde di una riga, e il verde di una riga non è il
verde dei suoi test.** Su questo repo si leggono i LOG.

## 2. I traguardi di questa sessione

- **I breakpoint software su macOS ora funzionano.** Non funzionavano affatto:
  `mach_vm_write` nel `__TEXT` falliva sempre perché nessuno alzava la
  protezione della pagina (579). Le due righe macOS sono ora verdi live inclusi.
- **Watchpoint dati e breakpoint hardware su ARM64 Linux** dove prima c'era un
  rifiuto (570, 571), e l'`ENOSPC` che ne bloccava cinque test è chiuso (589).
- **macOS riporta l'indirizzo di fault** (595): prima rispondeva «è crashato» e
  mai «dove».
- **Windows ha una CI** (597), per la prima volta: prima era verificato su una
  macchina sola, quella di sviluppo.
- **L'MCP dice tre verità nuove**: `"note"` sui watchpoint non riarmati (568),
  `capabilities` col motivo di ogni assenza (577), `"fault"` portabile (582).

## 3. Le tre famiglie di difetti che questo crate produce

1. **Un fallimento riportato come successo.** `let _ =`, `else { continue }`, un
   `bool` in cui «non trovato» e «non riuscito» collassano, uno step CI
   `continue-on-error` il cui esito non risale, una scrittura dimensionata male
   che riesce senza armare nulla, un `Drop` che lascia una trappola in silenzio.
2. **Logica condivisa che deriva.** Fra i tre backend, fra backend e MCP, fra i
   due lati dello stesso test, e fra una capacità DICHIARATA e il codice che la
   nega.
3. **Un'assunzione x86 in codice che gira anche su ARM.** Byte di trappola,
   allineamento, nomi dei registri, PC al trap, PAC, numero di slot di debug.

## 4. Difetti aperti — dichiarati, non nascosti

| Cosa | Dove | Stato |
|---|---|---|
| **PAC nell'unwinder** | Linux ARM | 573 non era mai stato ESEGUITO (ptrace dal thread sbagliato); rifatto al 591, **non ancora misurato** |
| **Byte di trappola nel test** | Linux ARM | corretto al 590, non ancora misurato |
| **Indirizzo staged in DR0** | Linux ARM | corretto al 594, non ancora misurato |
| **Watchpoint hw su Windows ARM** | Windows | rifiutati; la capacità ora lo DICHIARA (598). Implementabili — il CONTEXT ARM64 ha `Bcr`/`Bvr`/`Wcr`/`Wvr` — quando la riga CI potrà misurarlo |
| **Eventi di thread** | macOS, iOS | Mach e RSP non li consegnano. Dichiarati assenti col motivo, non simulati |
| **`task_for_pid` richiede root** | macOS | vincolo di piattaforma. ⚠️ **decisione dell'utente** |
| **iOS su hardware** | infrastruttura | i runner ospitati non hanno iPhone: serve self-hosted. Il simulatore però è arm64 REALE |
| **`continue-on-error`** | CI ×3 | da togliere riga per riga quando diventa verde |
| **14 file `.bak*`** | `src/` | ⚠️ **decisione dell'utente** |

## 4-bis. L'audit Windows, e cosa ha insegnato (601-604)

Tre difetti segnalati, tutti reali, **e due non erano dove l'audit li metteva**.

| # | Segnalato | Realtà misurata |
|---|---|---|
| 1 | `LibraryLoad { path: "" }`, da risolvere nell'evento | Risolverlo lì **rompe i watchpoint hardware** (guard stabilito per bisezione). La risoluzione esiste già, condizionata di proposito: costa un `modules()` a ogni DLL. Spostata alla superficie MCP, dove la paga chi guarda |
| 2 | `address`/`addr`, `size`/`len` incoerenti | L'indirizzo è **consistente** (`addr` ×12): il tentativo con `address` era il chiamante che indovinava. A divergere è la QUANTITÀ — `size`, `len`, `n` in tool adiacenti. Sinonimi ora accettati, col nome documentato che vince |
| 3 | `resolve_symbol` senza fallback EAT | Confermato in pieno. Quattro pezzi già presenti e nessuno collegato: la dipendenza `rustre-loader-pe`, `export_by_name`, `debug.modules` coi path, e `symbol_resolver.rs` che cita «PE exports» nella propria doc |

Sul 604 il dettaglio che separa una risposta corretta da una plausibile:
l'indirizzo nella export table è relativo alla **base preferita del file**,
mentre il modulo è caricato dove l'OS l'ha messo. Senza sommare la base runtime
e sottrarre quella del file, il numero è verosimile e non punta a nulla.

## 4-ter. Windows ARM64: la riga che non era mai stata eseguita (602)

Il primo run della riga creata al 597 ha risposto in modo più netto di quanto il
codice raccontasse: non «i watchpoint sono rifiutati su ARM», ma **il file non
era compilabile** per quel target — `ctx.Dr6` unknown field, più `Rip`,
`EFlags` e ventuno altri nomi x86, nessuno protetto.

Port scritto leggendo i nomi dei campi dal `winnt.rs` di winapi nel registry,
non indovinandoli. Tre scelte che evitano altrettanti difetti di famiglia 1:
niente `dr0`-`dr7` pubblicati su ARM (il motore crederebbe di avere quattro slot
su una CPU che ne espone **due**), entrambe le grafie `fp`/`x29` accettate (una
sola ignorerebbe in silenzio metà dei chiamanti), e `watchpoint_hit` che
risponde `None` come misura, non come segnaposto.

## 5. Lezioni di metodo

1. **Misurare il rosso PRIMA del fix.** Un test che passa senza aver mai fallito
   non dimostra nulla; se passa al primo colpo, va **perturbato**.
2. **Ancorare a un IDENTIFICATORE, mai a una stringa** che può comparire in
   prosa. Costato quattro volte: verde a vuoto, rosso falso, e un guard
   soddisfatto dai propri commenti.
3. **Un test può passare A VUOTO** dove i `cfg` lo compilano via. Misurare il
   rosso sulla piattaforma dove l'asserzione significa qualcosa.
4. **Un fallimento indistinguibile da una risposta negativa è taciuto.**
5. **Un flag di contabilità propria non misura il target.** Per ogni campo
   pubblicato: *misura il target o misura noi?*
6. **Risalire la catena prima di dichiarare chiuso.**
7. **Correggere una copia su due lascia il difetto** — fra backend, fra livelli,
   fra i due lati di un test, e fra dichiarazione e codice.
8. **Un rifiuto esplicito NON è un difetto**: è una difesa che funziona.
9. **La cautela su una premessa non verificata non è cautela.**
10. **Il difetto sta spesso nella FRASE**: portata dichiarata troppo larga,
    previsione scritta al presente, `SAFETY` falsa, parametro documentato e mai
    letto, una capacità dichiarata che il backend nega.
11. **L'assenza di un fallimento non è la presenza di un successo.** Tre grafie:
    cancelled (556), tollerato su Linux (572) e su macOS (578).
12. **Correggere prima la MISURA, poi il difetto.** Ogni volta che l'ho fatto la
    misura riparata ha rivelato qualcosa di grosso: il 578 ha scoperto che i
    breakpoint software su macOS non avevano mai funzionato.
13. **Non far passare un test nel modo più rapido.**
14. **Un ciclo che riprende il target va limitato dagli EVENTI**: un limite sui
    TENTATIVI non è un limite sul TEMPO. Costato 87 minuti di CI.
15. **Un job ucciso dal proprio timeout cancella il segnale di ogni altro test.**
16. **Verificare le PROPRIE dichiarazioni del round precedente.** Ha prodotto
    difetti reali sei volte: 581, 583, 587, 588, 595, 598.
17. **Chiedere al kernel invece di assumere**: maschera PAC, numero di slot,
    dimensione di pagina. Ogni costante «ovvia» cablata era sbagliata su una
    delle due architetture.
18. **Misurare un albero in movimento non è misurare**: `git worktree` per il
    sorgente, un `CARGO_TARGET_DIR` per attore. Usato al 600, quando il workflow
    iOS aveva reso la suite non compilabile.
19. **Un ciclo di feedback che non torna vale quanto non avere CI** (599): 11
    run in gara, il più vecchio a 77 minuti e mai finito. Prima si ripara lo
    strumento.
