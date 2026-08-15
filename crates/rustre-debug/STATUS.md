# rustre-debug — stato misurato

> **Regola di questo file.** Ogni 4 iterazioni va riscritto da zero. Non è un
> registro storico: è un cruscotto. Se cresce per stratificazione smette di
> rispondere alla domanda per cui esiste — *a che punto siamo davvero?* — e
> diventa un archivio che nessuno rilegge. Riscrittura precedente: 560.
> Questa: **569**.
>
> **Ogni numero qui è misurato, mai dedotto.** Se una riga dice «non
> dimostrato», significa che nessuna macchina raggiungibile ha risposto a quella
> domanda, e va letta come una lacuna dichiarata, non come un dettaglio.

---

## 1. Dove siamo

Quattro backend — Windows (Win32 debug API), Linux (ptrace), macOS (ptrace BSD +
Mach), iOS (GDB Remote Serial Protocol verso `debugserver`) — con una superficie
MCP condivisa in `rustre-mcp-tools/src/tools/debug.rs`.

Il traguardo raggiunto e mantenuto: **tutte e quattro le piattaforme sono
ESEGUITE, non solo compilate.** Compilare è una verifica sulla sintassi;
eseguire è l'unica che risponde sul comportamento.

## 2. Semaforo (al 569)

| Piattaforma | Come è verificata | Esito |
|---|---|---|
| Windows x86_64 | suite locale | **2008 passed, 0 falliti** |
| Linux x86_64 | WSL, `--test-threads=1` | **1990 passed, 0 falliti** (al 568) |
| Linux aarch64 | CI `ubuntu-24.04-arm` | esegue; `continue-on-error` ancora presente, da togliere quando il prossimo run lo dimostra |
| macOS Intel | CI `macos-15-intel` | esegue dopo il fix del tetto a 90′ (564) |
| macOS Apple Silicon | CI `macos-14` | esegue |
| iOS Simulator | CI | esegue |
| iOS device | CI | **solo compilazione** — serve un runner self-hosted con hardware |
| MCP | suite locale | **392 passed, 0 falliti** |
| Darwin ×2 | `cargo check` locale | entrambi compilano |

## 3. Le tre famiglie di difetti che questo crate produce

Non è una tassonomia teorica: quasi ogni iterazione recente cade in una di
queste, e riconoscerla è ciò che rende veloce il round successivo.

1. **Un fallimento riportato come successo.** `Ok(())` letterale, `let _ =`,
   `else { continue }`, o un `bool` in cui «non trovato» e «non riuscito»
   collassano. È la famiglia più numerosa e la più costosa: compila, passa i
   test, e mente al chiamante.
2. **Logica condivisa in tre copie che deriva.** I tre backend hanno lo stesso
   corpo per la stessa operazione; una copia viene corretta e due no.
   `the_logic_shared_by_the_three_backends_stays_identical` esiste per questo e
   ha già impedito una deriva (569).
3. **Un'assunzione x86 in codice che gira anche su ARM.** Byte di trappola,
   allineamento, nomi dei registri, PC riportato al trap. I round 548-563 hanno
   sistematicamente sostituito le costanti con derivazioni dall'architettura.

## 4. Iterazioni 566-569 — un unico difetto in quattro strati

566, 567 e 568 sono risultati **lo stesso difetto a tre livelli della catena**,
trovati risalendola. Chiudere solo quello di mezzo avrebbe prodotto valore zero.

| # | Strato | Difetto | Esito |
|---|---|---|---|
| 566 | produttore, foglia | `disarm_watchpoint_registers`: una scrittura fallita lasciava `found = false`, la stessa risposta di «mai armato» — e il chiamante cancellava la contabilità su quel `false`, dimenticando un watchpoint ancora vivo nei registri | propagato nei 3 backend; nell'MCP invertito l'ordine disarmo/liberazione-id |
| 567 | produttore, aggregato | `rearm_watchpoints_on_new_threads` aveva già la lista `unarmed` per riportare i thread scoperti, e di **quattro** modi di lasciarne uno scoperto ne raccoglieva **uno** | fix verificativo: si chiede ai registri cosa manca, invece di riportare a ogni sito |
| 568 | chiamante | i sei `let _ = self.rearm_watchpoints_on_new_threads().await;` buttavano via la lista appena completata | registrata in `unarmed_since_resume`, esposta via `Breakpoint.label` e come `"note"` in `debug.watchpoints` |
| 569 | difesa obsoleta | il rifiuto dei breakpoint software fuori da x86 citava un `int3` che la funzione **non impianta più**: venti righe sotto scrive `host_trap_bytes()`, cioè `BRK #0` su AArch64 | rimosso nei 3 backend; resta il solo rifiuto per allineamento |

**Il guadagno per l'utente del 568 merita di essere detto esplicitamente.**
`debug.watchpoints` pubblicava `"enabled": true`, che è contabilità *nostra* —
«l'utente non l'ha disabilitato» — e veniva letto come «la CPU sta
sorvegliando». Quando un re-arm mancava un thread i due divergevano e l'API
continuava a dire `true`. Ora accanto compare
`"note": "not armed on every thread as of the last resume"`.

**Il 569 in dettaglio, perché è quello dove ho sbagliato due volte.** Avevo
limitato la rimozione a Linux con una motivazione che suonava rigorosa — «solo
il runner ARM può dimostrarlo». La premessa era falsa: `macos-14` è Apple
Silicon e già esegue quei test. E il guard sull'identità dei tre backend ha
rifiutato la divergenza, correttamente: un byte di trappola derivato
dall'architettura è logica condivisa, non specificità di piattaforma. Aggiornati
insieme al fix, deliberatamente: `plant_software_bp` (l'allineamento resta
l'unico rifiuto ammesso, così un rifiuto generico reintrodotto non passa), il
test live macOS che era *progettato* per fallire quel giorno, e i due guard
sorgente preservandone l'intento.

## 4-bis. Iterazione 570 — watchpoint hardware su ARM64 Linux

Il gap funzionale più grande rimasto: un debugger senza watchpoint su ARM non è
enterprise. Linux rifiutava con *«this backend programs the x86 debug registers,
which this host architecture does not have»* — vero sulla seconda metà, ptrace
su AArch64 non espone `DR0`-`DR7`, e proprio per questo il round **non** è stato
«togliere un rifiuto» come il 569.

Quello che il crate possedeva già, e che ha ridotto il round da giorni a ore:

| pezzo | dov'era |
|---|---|
| semantica — cosa scrivere in `DBGWVR`/`DBGWCR` | **`lib.rs`**, condivisa, testata, già usata da macOS |
| trasporto `PTRACE_GETREGSET` + `iovec` | scritto al 552 per `NT_PRSTATUS` |
| layout `user_hwdebug_state`, `NT_ARM_HW_WATCH` | scritto ora |

La forma è copiata da macOS e non è una scelta di stile: la traduzione lavora
sull'intero `RegisterSet` (`merge_debug_state` / `write_debug_registers`) perché
`WVR`/`WCR` si calcolano da `dr{n}` **e** `dr7` insieme — una cucitura per
singolo registro non potrebbe esprimere `dr0` senza già conoscere `dr7`. Tutto
ciò che sta sopra quella linea resta byte-identico agli altri backend.

### Cosa è verificato e cosa no — la parte importante

| | esito |
|---|---|
| Trasporto + layout, type-check per `aarch64-unknown-linux-gnu` | ✅ **verificato** |
| `assert!(size_of::<UserHwdebugState>() == 264)` sul target reale | ✅ **passa** |
| Nessuna regressione sul percorso x86 | ✅ suite Windows e Linux |
| Le due cuciture nel command loop, compilate | ❌ **non verificato** |
| I registri vengono programmati CORRETTAMENTE | ❌ **non verificato** |

**Il «2009 passed» su Windows non prova nulla di questo codice**: sta sotto
`#[cfg(target_arch = "aarch64")]` e su Windows non viene compilato. Due strade
per compilarlo davvero sono fallite — `cargo check --target
aarch64-unknown-linux-gnu` da Windows richiede un cross-compiler C per
`libsqlite3-sys`, e installarlo in WSL richiede una password sudo. La terza ha
funzionato: il blocco è stato copiato **verbatim** in un crate di scratch con il
solo `libc` e type-checkato per il target ARM reale. Copiato, non parafrasato —
altrimenti avrei verificato una parafrasi.

Resta che la prova del comportamento può darla solo `ubuntu-24.04-arm`.

### Cosa il 570 NON ha portato

Watchpoint **dati** (`DataWrite`, `DataReadWrite`), non «i watchpoint su ARM».
Gli slot di ESECUZIONE — `rw == 0b00` in `DR7`, cioè i breakpoint hardware —
finiscono nel ramo `None` della traduzione, che li azzera. È corretto e
deliberato, e il commento in `lib.rs` lo diceva già prima di questo round:
*«AArch64 puts those in `DBGBVR`/`DBGBCR`, so there is no watchpoint pair that
expresses it; saying so beats arming a data watchpoint that would fire on the
wrong events»*.

Va però riletto alla luce del 570: quel `None` non significa più «non
supportato su questa piattaforma», significa **«esiste, dietro l'altro
regset»**. È il 571, ed è il gemello di questo round — `NT_ARM_HW_BREAK`,
`DBGBVR`/`DBGBCR`, una coppia di traduzione per gli slot di esecuzione —
riusando per intero il trasporto appena scritto: cambia l'id del regset e il
campo della struct, non il meccanismo.

### La correzione che ha salvato il round dall'essere inutile

`debug_registers_available` asseriva che su ARM `dr0` è RIFIUTATO e restituiva
`false`, facendo **saltare tutti i test dei watchpoint** su quella piattaforma.
Lasciato com'era, sarebbe successo questo: la riga `ubuntu-24.04-arm` sarebbe
diventata **verde senza eseguire una sola riga** del codice del 570, e quel verde
si sarebbe potuto spacciare per una dimostrazione.

Sarebbe stato il fallimento «guard vacuo» che questo file nomina altrove, con
l'aggravante del verde a coprirlo. Invertirlo non è un effetto collaterale del
round: è ciò che rende `ubuntu-24.04-arm` una MISURA invece che una conferma di
comodo. Ora un rifiuto lì dice esattamente cosa è rotto — *«a refusal here means
that translation did not reach the register set»*.

**Terza volta in due round che un guard scritto da iterazioni precedenti
intercetta una mossa di chi lavora oggi**: l'identità dei tre backend e il test
live macOS al 569, questo al 570. Nessuno aggirato, tutti aggiornati
deliberatamente. È la prova che scrivere guard che ASSERISCONO invece di
SALTARE ripaga: fanno da controllo su chi scrive, non solo sul codice.

## 4-ter. Iterazione 571 — breakpoint hardware su ARM64 Linux

Il gemello del 570, e la chiusura della lacuna che quel round aveva lasciato
aperta: gli slot di ESECUZIONE (`rw == 0b00` in `DR7`) cadevano nel ramo `None`
e venivano azzerati, quindi un breakpoint hardware su ARM veniva **accettato e
poi silenziosamente non armato**.

Aggiunti: la coppia `arm64_breakpoint_from_dr_slot` /
`dr_slot_from_arm64_breakpoint` in `lib.rs`, accanto a quella dei watchpoint, e
il regset `NT_ARM_HW_BREAK` accanto a `NT_ARM_HW_WATCH` — le due funzioni di
trasporto del 570 sono state generalizzate sull'id del regset invece di essere
duplicate.

**L'unica vera decisione di progetto** è la mappatura degli slot: x86 condivide
quattro slot fra breakpoint e watchpoint, AArch64 tiene **due file separati**,
ciascuno con i propri. Uno slot `dr` va quindi in **esattamente uno** dei due
secondo i bit `rw`, e nell'altro viene azzerato. Programmarli entrambi
significherebbe uno slot armato come due cose diverse, e un disarmo successivo
ne troverebbe una e riporterebbe successo.

L'assenza del regset dei breakpoint è tollerata in LETTURA (un kernel senza
quel file ha comunque watchpoint usabili: fallire entrambi butterebbe via
funzionalità che funziona per segnalare una lacuna) e PROPAGATA in scrittura
(un breakpoint richiesto e non programmato non va riportato come armato).

### Il mio guard era vacuo, ed è la parte istruttiva

La prima stesura asseriva `src.contains("NT_ARM_HW_BREAK")` ed è passata **al
primo colpo** — non perché il trasporto esistesse, ma perché quella stringa era
già nel file, dentro il TESTO di un messaggio di rifiuto scritto al 552. Il
guard era soddisfatto da della prosa.

L'ho notato solo perché un test che passa senza aver mai fallito insospettisce
(lezione 1); la causa è la lezione 7, un guard ancorato a una stringa. Riancorato
su `dr_slot_from_arm64_breakpoint` — che un commento non può soddisfare — il
rosso è arrivato vero. **Lezione 7, corollario: ancorare a un IDENTIFICATORE che
deve esistere per compilare, mai a una stringa che può comparire in un
commento.**

Stessa disciplina di verifica del 570, con lo stesso limite: type-check reale su
`aarch64-unknown-linux-gnu` (e verificato che fosse una compilazione vera, non
una cache), comportamento **non verificato** — risponde `ubuntu-24.04-arm`.

## 5. Il fronte Apple

Tre giri di workflow multi-agente con verifica avversariale. Il terzo: **104
agenti, 31 difetti trovati, 6 confermati, 25 confutati, 9 chiusi.** Il rapporto
25/31 confutati è il dato che conta — significa che la verifica sta scartando i
plausibili-ma-falsi invece di accumulare risultati.

## 6. Difetti aperti — dichiarati, non nascosti

| Cosa | Dove | Perché non è chiuso |
|---|---|---|
| **Breakpoint sw su ARM64: rimozione non ancora dimostrata** | 3 backend | Il rifiuto è stato tolto al 569. `ubuntu-24.04-arm` e `macos-14` lo dimostreranno; **Windows-on-ARM non ha runner: strutturalmente identico, non dimostrato.** |
| **`task_for_pid` richiede root** | macOS | Vincolo di piattaforma (555). Serve decidere fra entitlement ed esecuzione privilegiata. ⚠️ **decisione dell'utente**. |
| **Registri di debug su ARM64** | Linux | `Unsupported` esplicito: `NT_ARM_HW_BREAK`/`NT_ARM_HW_WATCH` sono un sottosistema, non una rinominazione. |
| **Watchpoint hw su ARM64** | Linux | Stesso motivo: il backend programma i registri di debug x86. |
| **Indirizzo faultante** | macOS | Via identificata (`__far` via `thread_get_state`), non implementata: senza poter eseguire, un offset sbagliato darebbe un indirizzo plausibile e falso — peggio di `None`. |
| **Eventi thread** | macOS | Nessun equivalente di `PTRACE_O_TRACECLONE`. |
| **Canonico del frame pointer** | crate | `x29` vs `fp`: il 552 pubblica **entrambi** per non decidere di nascosto. ⚠️ **decisione dell'utente**. |
| **iOS su hardware** | infrastruttura | Non ottenibile su Actions: serve un runner self-hosted. |
| **`continue-on-error` su Linux aarch64** | CI | Da togliere appena un run verde lo dimostra. Toglierlo ora renderebbe la CI rossa per una previsione. |
| **14 file `.bak*`** | `src/` | ⚠️ **decisione dell'utente**. |

## 7. Lezioni di metodo

Consolidate: le 26 accumulate fino al 569 si riducono a queste, che sono quelle
che hanno effettivamente cambiato il modo di lavorare.

1. **Misurare il rosso PRIMA di dichiarare il fix.** Un test che passa senza aver
   mai fallito non dimostra nulla (559). Se il fix è già scritto, revertirlo per
   vedere il rosso e poi ripristinarlo. Vale anche per il tempismo: un test può
   passare perché nessuno lo rompe, non perché il codice è giusto (560).
2. **Un fallimento che non si distingue da una risposta negativa è un
   fallimento taciuto** (566). Non serve un `Ok(())` per mentire: basta un
   `bool` in cui «non trovato» e «non riuscito» collassano.
3. **Un commento che giustifica l'azione non giustifica lo scarto del suo
   esito** — vista 9 volte, da ultimo al 568. `let _ =` non scarta il
   fallimento, scarta l'informazione.
4. **Quando una funzione si è già data un modo di riportare un fallimento,
   controllare che TUTTI i suoi fallimenti lo usino** (567). Un meccanismo di
   report presente è più insidioso di uno assente: a lettura veloce sembra che
   il caso sia coperto.
5. **Preferire un fix verificativo a uno additivo** (567). Riportare a ogni sito
   di fallimento è fragile e sovra-riporta; chiedere *dopo* allo stato reale
   «cosa manca davvero?» copre anche i percorsi non enumerati.
6. **Un flag di contabilità propria non è una misura dello stato reale** (568).
   Per ogni campo pubblicato: *questo misura il target o misura noi?*
7. **Risalire la catena prima di dichiarare chiuso** (566→568). Il fix a metà
   catena vale zero se il chiamante butta via il risultato.
8. **Correggere una copia su due lascia il difetto** — orizzontalmente fra i tre
   backend (553) e verticalmente fra backend e MCP (566).
9. **Cosa c'è davvero dietro il nome che sto per cambiare?** Una difesa che
   sembra obsoleta può proteggere qualcosa di vivo (14, 548, 557) e
   un'implementazione che sembra sbagliata può essere un'astrazione condivisa
   (561, **iterazione ritirata**). Il 569 è il caso in cui la difesa era
   davvero obsoleta — e la differenza non è stata il giudizio ma l'evidenza.
10. **La cautela costruita su una premessa non verificata non è cautela** (569).
    Avevo limitato un fix «perché nessuno può dimostrarlo», e un runner che
    poteva dimostrarlo esisteva già.
11. **Rendere un controllo severo alla cieca è un difetto nuovo** (544, 554,
    567). Un falso allarme non è un passo verso la correttezza.
12. **Misurare un albero in movimento non è misurare** (551). Più agenti
    scrivono in questo workspace: usare `git worktree` per il sorgente e un
    `CARGO_TARGET_DIR` per attore. La contesa sul target dir condiviso ha già
    bloccato build per decine di minuti senza alcun errore di compilazione.
13. **L'assenza di un fallimento non è la presenza di un successo** (556). Un
    job cancellato non è un job passato; `= success`, mai `!= failure`.
14. **Un elenco di piattaforme si verifica compilando, non rileggendo**; e un
    comportamento si verifica eseguendo, non compilando.
