# rustre-debug — stato misurato

> **Regola.** Ogni 4 iterazioni questo file va riscritto DA ZERO. È un cruscotto,
> non un registro. Precedente: 608. Questa: **613**.
>
> **Ogni numero è misurato.** «Non dimostrato» = nessuna macchina raggiungibile
> ha risposto: lacuna dichiarata, non dettaglio.

---

## 1. Semaforo

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

## 2. Cosa funziona oggi che non funzionava ieri

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

## 3. Le tre famiglie di difetti che questo crate produce

1. **Un fallimento riportato come successo**: `let _ =`, `else { continue }`, un
   `bool` in cui «non trovato» e «non riuscito» collassano, uno step CI
   `continue-on-error` il cui esito non risale, una scrittura dimensionata male,
   un `Drop` che lascia una trappola in silenzio.
2. **Logica condivisa che deriva**: fra i tre backend, fra backend e MCP, fra i
   due lati dello stesso test, fra una capacità DICHIARATA e il codice che la
   nega.
3. **Un'assunzione x86 in codice che gira anche su ARM**: byte di trappola,
   allineamento, nomi dei registri, PC al trap, PAC, numero di slot, trap flag.

## 4. Difetti aperti — dichiarati

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

## 5. Lezioni di metodo

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
