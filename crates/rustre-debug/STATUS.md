# rustre-debug — stato misurato

> **Regola di questo file.** Ogni 4 iterazioni va riscritto DA ZERO. Non è un
> registro: è un cruscotto. La riscrittura precedente (569) è stata seguita da
> sei sezioni `4-bis`…`4-sexies` appiccicate in coda — esattamente la
> stratificazione che la regola vieta, e il motivo per cui questa riscrittura
> era in ritardo. Questa: **581**.
>
> **Ogni numero è misurato.** Dove si legge «non dimostrato» significa che
> nessuna macchina raggiungibile ha risposto: è una lacuna dichiarata, non un
> dettaglio.

---

## 1. Semaforo

| Dove | Come è verificato | Esito |
|---|---|---|
| Windows x86_64 | suite locale | **2014 / 0** |
| Linux x86_64 | WSL, `--test-threads=1` | **1997 / 0** |
| Linux aarch64 | CI `ubuntu-24.04-arm` | **1946 / 6** su `1c70fff`; i 6 affrontati in 573-575, esito del run successivo da leggere |
| macOS Intel | CI `macos-15-intel` | suite **1925 / 0**, MCP 362/0, **live 2 falliti** |
| macOS Apple Silicon | CI `macos-14` | suite **1925 / 0**, MCP 362/0, **live 2 falliti** |
| iOS Simulator | CI | **1923 / 0** |
| iOS device | CI | **compila soltanto** — nessun test, serve un runner self-hosted |
| MCP | suite locale | **392 / 0** |
| Darwin ×2 | `cargo check` | 0 errori |
| Codice ARM64 Linux | harness `libc`-only su `aarch64-unknown-linux-gnu` | type-check ✅ |

**Il verde di un job non è il verde di una riga, e il verde di una riga non è il
verde dei suoi test.** Su questo repo vanno letti i log: entrambe le righe macOS
concludono `success` con live test rossi dentro.

## 2. Le tre famiglie di difetti che questo crate produce

Quasi ogni iterazione recente cade in una di queste. Riconoscere la famiglia è
ciò che rende veloce il round successivo.

1. **Un fallimento riportato come successo.** `Ok(())` letterale, `let _ =`,
   `else { continue }`, un `bool` in cui «non trovato» e «non riuscito»
   collassano, uno step CI `continue-on-error` il cui esito non risale.
   La più numerosa e la più costosa: compila, passa, e mente al chiamante.
2. **Logica condivisa in tre copie che deriva.** Stesso corpo nei tre backend;
   una copia corretta e due no.
   `the_logic_shared_by_the_three_backends_stays_identical` ha già impedito una
   deriva che stavo per introdurre (569).
3. **Un'assunzione x86 in codice che gira anche su ARM.** Byte di trappola,
   allineamento, nomi dei registri, PC riportato al trap, PAC.

## 3. Cosa funziona oggi che prima non funzionava

- **Watchpoint dati su ARM64 Linux** (570) — `NT_ARM_HW_WATCH`.
- **Breakpoint hardware su ARM64 Linux** (571) — `NT_ARM_HW_BREAK`.
- **Breakpoint software su ARM64** ovunque (569) — il rifiuto citava un `int3`
  non più impiantato.
- **PAC tolto nell'unwinder DWARF di Linux** (573) — con la maschera chiesta al
  kernel, non con la costante di Apple.
- **`mach_vm_protect` su macOS** (579) — senza cui `mach_vm_write` nel `__TEXT`
  falliva sempre: i breakpoint software su macOS non avevano MAI funzionato.
- **L'MCP dice due verità nuove**: `"note"` sui watchpoint non riarmati su tutti
  i thread (568), e `capabilities` con il motivo di ogni assenza (577).
- **`AccessViolation.address` è il dato, non l'istruzione** (581) — Windows
  riportava `ExceptionAddress` (l'istruzione) dove Linux riporta `si_addr` (il
  dato). Un campo, due significati secondo l'OS, e nessuno dei due errava: chi
  lo confrontava con un buffer otteneva l'indirizzo del codice e ci credeva.
  A dirimere è la variante stessa — porta UN indirizzo e accanto `is_write`, che
  descrive l'accesso ai dati: un indirizzo che non è quel dato rende la coppia
  auto-contraddittoria. L'istruzione non si perde, è il PC allo stesso stop.

  **Trovato verificando le affermazioni del 577**, cioè le mie. Avevo appena
  creato una superficie che DICHIARA fatti; darle per buone senza controllarle
  avrebbe aggiunto un'API sicura di sé all'elenco che questa sessione sta
  chiudendo. Le tre capacità reggevano; sotto c'era questo.

- **Una domanda, una risposta portabile** (582) — lo stesso crash arrivava in
  tre forme: `AccessViolation` su Windows, `Signal { SIGSEGV, address }` su
  Linux, `Signal { SIGSEGV, address: None }` su macOS. E `AccessViolation` è
  COSTRUITO solo dal backend Windows — in Linux quel nome vive soltanto nei
  commenti — quindi il `match` ovvio funzionava su Windows e su altrove **non
  scattava mai**, pur essendo avvenuto il crash: nessun errore, ramo morto.

  `StopReason::access_fault()` legge la forma arrivata e riporta ciò che quel
  backend SA, con gli ignoti scritti come ignoti. **Normalizzare era la
  tentazione sbagliata**: far emettere `AccessViolation` a Linux avrebbe
  richiesto un `is_write` non derivabile da `si_addr`, cioè fabbricato.
  Esposto nell'MCP come campo `"fault"` in tutti e 5 i punti che pubblicano un
  evento, così un client non deve fare parsing di una stringa `Debug` né sapere
  quale OS l'ha prodotta. `null` distingue «non è un fault» da «è un fault ma
  l'OS non riporta quel dato».

  Verificato per perturbazione: degradando `is_write: None` a `Some(false)` —
  «sconosciuto» che diventa «era una lettura» — il test va rosso.

- **583 — il falso positivo che avevo introdotto io nel 582.** `access_fault`
  accettava `11 | 10 | 7` ovunque, con un commento che RICONOSCEVA che `SIGBUS`
  cambia numero fra piattaforme e lo «risolveva» accettandoli entrambi. Ma quei
  numeri non sono liberi dall'altra parte:

  | numero | Linux | macOS |
  |---|---|---|
  | 7 | `SIGBUS` | **`SIGEMT`** |
  | 10 | **`SIGUSR1`** | `SIGBUS` |

  Quindi un normalissimo `SIGUSR1` veniva riportato come fault di memoria su
  Linux. Per un round è stato **peggio** del difetto che correggeva: prima il
  ramo era morto, dopo era attivo e mentiva. *L'unione delle costanti di due
  piattaforme non è una costante portabile.*

  Il test passava A VUOTO su Windows, dove i `cfg` sono compilati via: il rosso
  è stato misurato in WSL, l'unica piattaforma dove quell'asserzione significa
  qualcosa.

- **584 — «l'indirizzo» erano due cose, e la doc ne prometteva una.**
  `StopReason::address()` diceva *«the address associated with this stop
  event»* e restituiva indirizzi di CODICE per `Breakpoint`/`SingleStep`/
  `LibraryLoad` e il DATO toccato per `AccessViolation`/`Signal`. Chi credeva
  alla frase e disassemblava otteneva l'istruzione per un breakpoint e un
  puntatore a dati per un segfault, senza nulla che segnalasse la differenza.

  **Onestamente: nessun chiamante lo usa male oggi** — gli unici consumatori
  sono test e l'MCP non lo pubblica. La trappola è latente; il difetto
  PRESENTE è la frase, sesta volta in questa sessione.

  Il 581 non ha causato l'ambiguità (`Signal` restituiva già `si_addr`) ma l'ha
  resa massima, togliendo l'ultima variante in cui i due tipi coincidevano per
  caso su Windows. `address()` resta — «dammi qualunque indirizzo» è legittimo
  per logging — e accanto c'è `code_address()`, che per i fault risponde `None`
  invece di restituire un dato. `Exception` è escluso di proposito: il suo
  indirizzo è l'istruzione su Windows ma la variante è usata anche per stop
  riempiti da altre fonti, e promettere «questo è codice» sarebbe una garanzia
  che il tipo non può mantenere.

- **585 — il blocco che avevo introdotto io nel 574, e il suo costo.**

  | step, riga aarch64 | durata |
  |---|---|
  | `Build (release)` | 3 min |
  | `Test (release, serial)` | **87 min → ucciso dal tetto** |
  | stesso step, un commit prima | **1,59 secondi** |

  Non lentezza dell'ARM. Nel 574 avevo riscritto un ciclo come «riprendi finché
  non vedi due thread»: si legge bene e si blocca, perché **un resume non è
  gratis** — aspetta lo stop successivo. Se il target non ha altri stop da dare,
  cioè esattamente il caso ARM che stavo diagnosticando, la PRIMA attesa non
  torna mai. Il `for _ in 0..64` sembrava prudente ma limitava i TENTATIVI, non
  il TEMPO.

  **Il costo supera il test**: un job ucciso dal proprio tetto cancella il
  segnale di ogni altro test al suo interno, quindi le correzioni di 573 e 575
  — già spinte e pronte — non sono mai state misurate su ARM.

  I due cicli vicini nello stesso file erano CORRETTI (`_ => break`: riprendono
  solo finché arrivano eventi di quel tipo, quindi sono limitati dagli eventi
  reali). Il codebase aveva già l'idioma giusto e me ne sono allontanato io.

  Tetto alzato a 120 min, ma scrivendo nel workflow che la causa era il blocco e
  che **a 120 non va rialzato**: significherebbe che qualcosa si blocca di nuovo
  e il numero lo starebbe nascondendo. Alzare un timeout è la reazione istintiva
  e quasi sempre quella che nasconde il problema.

  Conferma collaterale: `Linux verified` ha riportato **failure** su quel run —
  il fix del 572 che funziona in produzione, dove prima una riga cancellata
  sarebbe passata in silenzio.

## 4. Difetti aperti — dichiarati, non nascosti

| Cosa | Dove | Perché non è chiuso |
|---|---|---|
| **Live test macOS rossi** | macOS ×2 | 579 e 580 li affrontano; **non dimostrato**, risponde il prossimo run |
| **`pthread_create` espone 1 thread** | Linux ARM | 574 lo ha reso DIAGNOSTICO, non risolto: dirà se manca l'evento o l'enumerazione |
| **Eventi di thread** | macOS | Mach non ha equivalente di `PTRACE_O_TRACECLONE`. Pubblicato come capacità assente (577) invece che simulato |
| **Indirizzo faultante** | macOS | `__far` via `thread_get_state`, non esposto da `mach2`; un offset sbagliato darebbe un indirizzo plausibile e falso |
| **`task_for_pid` richiede root** | macOS | Vincolo di piattaforma. ⚠️ **decisione dell'utente**: entitlement o esecuzione privilegiata |
| **Watchpoint ARM64 provati davvero** | Linux ARM | Compilano e la traduzione è testata; **se il kernel programmi quei registri correttamente non è verificato** |
| **`continue-on-error`** | CI Linux + macOS | Da togliere quando le righe sono verdi. Toglierlo ora renderebbe rossa la CI per difetti noti |
| **Canonico del frame pointer** | crate | `x29` vs `fp`: il 552 pubblica entrambi per non decidere di nascosto. ⚠️ **decisione dell'utente** |
| **iOS su hardware** | infrastruttura | Non ottenibile su Actions |
| **14 file `.bak*`** | `src/` | ⚠️ **decisione dell'utente** |

## 5. Lezioni di metodo

Consolidate. Solo quelle che hanno cambiato il modo di lavorare.

1. **Misurare il rosso PRIMA di dichiarare il fix.** Un test che passa senza aver
   mai fallito non dimostra nulla (559). Se il fix è già scritto, revertirlo per
   vedere il rosso. Un test che passa al primo colpo va guardato con sospetto:
   due volte era vacuo (571, 573).
2. **Ancorare un guard a un IDENTIFICATORE, mai a una stringa.** `NT_ARM_HW_BREAK`
   compariva nel testo di un rifiuto → verde vacuo (571). `ios::arm64::strip_pac`
   compariva nei miei commenti → rosso falso (573). La parentesi `foo(`
   distingue un uso da una menzione.
3. **Un fallimento indistinguibile da una risposta negativa è taciuto** (566).
   Non serve un `Ok(())` per mentire.
4. **Un commento che giustifica l'azione non giustifica lo scarto del suo
   esito** — vista 9 volte, da ultimo al 568.
5. **Quando una funzione si è già data un modo di riportare un fallimento,
   controllare che TUTTI i suoi fallimenti lo usino** (567). Un meccanismo
   presente è più insidioso di uno assente.
6. **Preferire un fix verificativo a uno additivo** (567): chiedere allo stato
   reale «cosa manca?» copre anche i percorsi non enumerati.
7. **Un flag di contabilità propria non misura il target** (568). Per ogni campo
   pubblicato: *questo misura il target o misura noi?*
8. **Risalire la catena prima di dichiarare chiuso** (566→568): un fix a metà
   catena vale zero se il chiamante butta via il risultato.
9. **Correggere una copia su due lascia il difetto** — fra i tre backend (553),
   fra backend e MCP (566), e fra i siti di uno stesso file: la CI segnalava 2
   `rip`, i siti erano 4 (575). *Il log dice quali test hanno fallito, non
   quanti siti hanno il difetto.*
10. **Cosa c'è davvero dietro il nome che sto per cambiare?** Una difesa che
    sembra obsoleta può proteggere qualcosa di vivo (548, 557); una che sembra
    viva può essere obsoleta (569); un'implementazione che sembra sbagliata può
    essere un'astrazione condivisa (561, **ritirato**).
11. **La cautela costruita su una premessa non verificata non è cautela** (569):
    avevo ristretto un fix «perché nessuno può dimostrarlo», e il runner che
    poteva dimostrarlo esisteva già.
12. **Il difetto sta spesso nella FRASE, non nel codice.** La portata dichiarata
    del 559, la diagnosi incompleta del 560, l'«attesa verde» nel workflow, una
    nota `SAFETY` che giustificava un `unsafe` con un'affermazione falsa (576),
    il mio «PROVEN by runners» scritto prima che i runner rispondessero (569).
    In un repo dove i commenti spiegano il PERCHÉ, un commento falso è un
    difetto: è ciò su cui si baserà chi legge dopo.
13. **L'assenza di un fallimento non è la presenza di un successo.** Tre grafie
    dello stesso sbaglio: *cancelled non è failure* (556), *un fallimento
    tollerato non è un fallimento* su Linux (572) e su macOS (578).
14. **Correggere prima la MISURA, poi il difetto.** Su entrambe le piattaforme il
    difetto grave è emerso solo dopo aver reso visibile il fallimento: su macOS
    il 578 ha rivelato il 579.
15. **Non far passare un test nel modo più rapido.** Non sintetizzare un evento
    che significherebbe meno di quello vero (577); non inventare un valore magico
    per una piattaforma sola (580); non ammorbidire una difesa corretta perché un
    test sceglie male l'indirizzo (575).
16. **Rendere severo alla cieca è un difetto nuovo** (544, 554, 567). Un falso
    allarme non è un passo verso la correttezza.
17. **Misurare un albero in movimento non è misurare** (551): `git worktree` per
    il sorgente e un `CARGO_TARGET_DIR` per attore. La contesa sul target dir
    condiviso ha bloccato build per decine di minuti senza alcun errore.
18. **Un comportamento si verifica eseguendo.** Compilare verifica la sintassi;
    per il codice che nessuna macchina locale può eseguire, la CI è l'unica
    risposta — e va resa non-vacua prima di fidarsene (570).
