# STATUS — `rustre-debug`

> **Cruscotto del debugger.** Aggiornato a **ogni iterazione**. Ogni numero qui è
> **misurato**, mai stimato: se una cosa non è stata misurata, è scritto che non
> lo è stata.
>
> **Ogni 4 iterazioni questo file va riscritto da zero**, non solo esteso: il
> semaforo e le dimensioni si rimisurano, i difetti chiusi escono dalla tabella
> degli aperti, le iterazioni vecchie si comprimono in una riga di totale. Un
> numero non rimisurato durante il consolidamento va marcato come non misurato.
> Motivo: un file che cresce per accumulo diventa una cronologia, non un
> cruscotto — le righe restano vere ma smettono di descrivere lo stato attuale.
>
> Ultimo aggiornamento: **iterazione 544** · 2026-08-15
> **Questa è una riscrittura completa** (544 = 4×136). Prossima: iterazione 548.

---

## 1. La cosa più importante, in cima

**Il backend macOS è stato ESEGUITO su hardware Apple reale, e ha passato.**

```
macOS Apple Silicon (aarch64)
  6. Build (release) ....... success
  7. Test (release, serial)  SUCCESS   ← mai prima in 539 iterazioni
```

Era il limite dichiarato del progetto da sempre. Non è stato chiuso da una
correzione: è stato chiuso scoprendo che il repo **non aveva nessun commit e
nessun remote** (`git rev-list --count HEAD` → errore), quindi il workflow macOS
esisteva ma non era mai partito. «macOS non è mai stato eseguito» non era un
difetto da correggere, era una conseguenza aritmetica.

⚠️ Cosa NON è ancora vero: **macOS Intel non ha mai girato** — vedi §6.

---

## 2. Semaforo

| Indicatore | Valore | Note |
|---|---|---|
| **Test Windows** (`rustre-debug --lib`) | **1918 / 1918** ✅ | rimisurato all'iterazione 544 |
| **Test Linux** (WSL, seriale) | 1901 / 1901 ✅ | ⚠️ misurato al **542**, non rimisurato al 544 |
| **Test MCP** (`rustre-mcp-tools --lib`) | 392 / 392 ✅ | ⚠️ misurato al **542**, non rimisurato al 544 |
| **macOS x86_64** (`cargo check`) | ✅ 0 errori | ⚠️ misurato al 542 |
| **macOS aarch64** (`cargo check`) | ✅ 0 errori | ⚠️ misurato al 542 |
| **Regressioni aperte** | **0** | nessuna ammessa per regola |

Il conteggio Windows è salito da 1887 a 1918 in quattro iterazioni: 6 guard test
miei e il resto dai test scritti dagli agenti sul fronte Apple.

### Copertura per piattaforma

| | Windows | Linux | macOS ARM | macOS Intel | iOS |
|---|---|---|---|---|---|
| Compila | ✅ | ✅ | ✅ | ✅ | ✅ ¹ |
| **Eseguito** | ✅ | ✅ | ✅ **nuovo** | ❌ mai | ❌ mai ² |
| Test live (processo reale) | 67 ³ | 34 ³ | 0 | 0 | 0 |

¹ `aarch64-apple-ios` **compila**, dall'iterazione 542. Prima di allora
`grep -r apple-ios` sul repo non trovava **nulla**: iOS era un backend che non
era mai stato un target di build.
² Il Simulator gira sul kernel macOS dell'host: nessun run su Actions è evidenza
su iOS. Serve hardware fisico e un runner self-hosted.
³ Non rimisurato in questo consolidamento.

---

## 3. Dimensioni

Rimisurate all'iterazione 544.

| Componente | File | Righe |
|---|---|---|
| `src/*.rs` (primo livello) | 55 | **70 489** |
| ├─ `lib.rs` (core + guard test) | | 12 193 |
| ├─ `windows_debugger.rs` | | 8 384 |
| ├─ `linux_debugger.rs` | | 5 458 |
| └─ `macos_debugger.rs` | | 4 523 |
| `src/ios/` (526 test) | 17 | **32 337** |
| `src/codeview/` | 15 | **19 539** |
| **`rustre-debug` totale** | **87** | **122 365** |
| `rustre-mcp-tools` — `tools/debug.rs` | 1 | 6 872 |

**Da ripulire**: 14 file `.bak*` in `src/`, entrati nel primo commit. Non sono
compilati (fuori dall'albero dei moduli): sono copie di backup, non
funzionalità non cablata. Rimozione non fatta — è una decisione dell'utente.

---

## 4. Reti di sicurezza

| Rete | Quantità | A cosa serve |
|---|---|---|
| Test **live** Windows | 67 ¹ | processo reale, breakpoint/watchpoint veri |
| Test **live** Linux | 34 ¹ | ptrace reale, fixture `pthread` compilate al volo |
| **Guard test sul sorgente** (`lib.rs`) | ~252 ¹ | l'unica lente che copre macOS senza eseguirlo |
| Test in `src/ios/` | **526** | rimisurato al 544; girano su **ogni** host |
| **CI macOS + iOS** | 4 job | **la rete nuova, e la più efficace** |

¹ non rimisurato in questo consolidamento.

I 526 test iOS girano su Windows e Linux per una scelta dichiarata in
`src/ios/mod.rs`: *nothing is gated on `cfg(target_os = "macos")`* — la
conoscenza Apple (layout Mach-O, compact-unwind, convenzioni ARM64) è aritmetica
su byte e registri, e solo l'accesso vero alle syscall sta dietro un trait.

**Regola di verifica** (rispettata a ogni iterazione): Windows + Linux eseguiti ·
MCP eseguito · entrambi i target Darwin compilati · **fail-first misurato** prima
di dichiarare un fix.

---

## 5. Iterazioni

### 516→540: compresse
19 difetti/gap corretti, 3 protezioni, 1 ritirata (bocciata da due guard, a
ragione), 1 misura senza consegna. Coprivano minidump, contesto x64/i386,
registri ARM64, eventi thread, pending breakpoint tri-OS, e quattro affermazioni
MCP fatte senza controllo.

### 540 — il rewind del breakpoint fallito
La CPU porta il PC oltre l'`int3` **prima** di sollevare l'eccezione.
`rewind_past_own_breakpoint` leggeva i registri sotto `if let Ok(..)` e li
riscriveva sotto `let _ =`: entrambi i fallimenti scartati, e il chiamante
riceveva `Ok(Breakpoint { address })` — vero su cosa è successo, **falso sullo
stato che ha lasciato**. Riprendendo, il target riparte *dentro* un'istruzione:
esecuzione arbitraria, non una risposta approssimata. Le tre funzioni erano
identiche byte-per-byte (`diff`). Firma → `Result<(), DebugError>`, sei chiamanti
aggiornati. Il conteggio dell'hit resta *prima* del rewind: il breakpoint è
scattato davvero.

### 541 — `ThreadExit`: un ramo corretto senza produttore
Un comando per-tid deve portare il thread in ptrace-stop, e il thread può morire
in quella finestra: `ensure_stopped` faceva `waitpid`, **consumava** l'uscita e
usciva. Il fail-first non è stato inventato — era già scritto in negativo nel
codice, che rinunciava deliberatamente ad asserirlo. Trasformata la rinuncia in
asserzione: `born=[ThreadId(542)] died=[]`, rosso su **processo reale**. Fix:
coda `deferred_exits`, consegnata da `ContinueExecution` **prima** di riprendere
alcunché — quell'evento riguarda un thread già morto, e `last_tid` resta intatto
perché il thread fermo è ancora quello che il prossimo continue deve riprendere.

### 542 — tre difetti, uno per piattaforma nascosta
**a)** Due rami adiacenti facevano l'opposto nella stessa situazione: il ramo
`tracked` scartava l'esito di rimettere a DISABILITATO un breakpoint riarmato per
lo step. Conseguenza: «step riuscito» con una trappola **armata** che l'utente
aveva spento. Ora propaga, ma solo se `result` è già `Ok` — un errore già in
viaggio dice più di questo.
**b)** Tre binding `#[cfg]` (Windows/Linux/macOS) e nessuno per iOS: `dbg` non
veniva mai legato e il nome si risolveva alla macro `dbg!` di std.
`error[E0423]` — **il crate non compilava**.
**c)** Otto `const fn` col corpo dentro `#[cfg(target_os = "linux")]`: su Windows
resta lo stub const-compatibile e il qualificatore passa. Sotto, protetto dal non
essere mai stato compilato: `ptrace::write(pid, addr, word as *mut c_void)` dove
`PTRACE_POKEDATA` vuole **il dato per valore**.

### 543 — una capacità mancante che rendeva i test non isolati
`cache_path` inchiodava `~/.rustre/pdb`. Ogni strumento di simboli lascia
configurare quella posizione (`_NT_SYMBOL_PATH`, `SRV*`, `DEBUGINFOD_URLS`),
perché su una macchina condivisa la home è la risposta sbagliata. Lo stesso
hard-coding rendeva i test **non isolati**: scrivevano in un percorso fisso sotto
la home reale, quindi due processi concorrenti collidevano. Aggiunto
`RUSTRE_PDB_CACHE`; i test usano un nome unico per processo.
Più: `call_tool` era `#[cfg(any(windows, target_os = "linux"))]` mentre i suoi
chiamanti non lo erano — su macOS i chiamanti esistevano e l'helper no. Tolto il
gate invece di aggiungerlo ai chiamanti: gatelo lì avrebbe spento ~30 smoke test
MCP proprio sulla piattaforma che stiamo verificando.

### 544 — `detach` rispondeva con una costante
Tutti e tre i backend emettevano le loro syscall di detach
(`DebugActiveProcessStop`, `PTRACE_DETACH` per thread, `PT_DETACH`), **scartavano
ogni ritorno**, e rispondevano `Reply::Ack(Ok(()))`. La risposta era un letterale.

Su Windows è il posto più costoso dove sbagliare: un processo che resta debuggato
viene **ucciso** quando il suo debugger esce, quindi al chiamante veniva detto di
aver lasciato andare il target e il target moriva col debugger.

Il fix **non** è «propaga tutto»: su Linux e macOS `ESRCH` è perdonato, perché un
thread morto o un processo già andato non hanno più nulla da cui staccarsi — che
è cosa significa «staccato». Qualunque altro errno (`EPERM`, `EINVAL`) dice che
il target è ancora lì e ancora nostro. È la stessa asimmetria già applicata in
`ensure_stopped`: *«Only ESRCH removes.»*

Su Windows nessun caso da perdonare, verificato non assunto: un processo già
uscito non raggiunge quel ramo, perché il loop eventi ritorna appena riporta
l'uscita e `send(Command::Detach)` fallisce su un canale morto.

---

## 5-bis. La CI, e cosa ha rivelato in due giorni

Il workspace **non si costruiva su nessun Unix**, per quattro cause indipendenti,
tutte nascoste da Windows:

| Causa | Visibile su |
|---|---|
| `pyo3-ffi 0.23.5` vs Python 3.14 del runner | macOS |
| `fuser` dipendenza obbligatoria (serve libfuse/macFUSE) | Linux, macOS |
| `#[path="../x.rs"]` in modulo **inline** → `src/element_type/` non esiste | Linux, macOS |
| `const fn` + `ptrace::write` mistipizzata | Linux |

Il terzo è il più istruttivo: Windows normalizza il `..` lessicalmente e apre il
file lo stesso; Linux e macOS risolvono componente per componente e falliscono.
Un difetto che **non può** manifestarsi sulla macchina di sviluppo.

**La CI ha trovato anche due difetti del workflow che l'aveva scritta**: i test
del Simulator giravano *prima* del boot (e un binario `aarch64-apple-ios-sim` non
è eseguibile su macOS senza `xcrun simctl spawn`), e il runner `macos-13` è
ritirato — l'etichetta viene accettata alla lettura e **mai schedulata**, che è
peggio di un fallimento perché non riporta mai nulla. Passato a
`macos-15-intel`.

### La lezione, che non è un aneddoto

542b, 543b e i tre difetti di build sono **la stessa cosa**: un `cfg` che elenca
le piattaforme a mano e ne dimentica una. Windows/Linux ma non macOS.
Windows/Linux/macOS ma non iOS. Non sono sviste indipendenti — il workspace è
stato scritto e verificato solo su Windows per tutta la sua vita, quindi ogni
elenco scritto a mano è rimasto non verificato per anni, e ogni livello di build
che si sblocca ne rivela un altro.

**539 iterazioni di ispezione del sorgente non hanno trovato ciò che un solo run
di CI ha trovato in venti minuti.** Non per distrazione: quei difetti sono
strutturalmente invisibili alla macchina di sviluppo. Un elenco di piattaforme si
verifica compilando per quelle piattaforme, non rileggendolo.

---

## 6. Difetti aperti — dichiarati, non nascosti

| Cosa | Dove | Perché non è chiuso |
|---|---|---|
| **macOS Intel mai eseguito** | CI | `macos-13` è ritirato e non veniva schedulato. Passato a `macos-15-intel` all'iterazione 544; **il primo run non è ancora stato letto**. |
| **Indirizzo faultante** | macOS | `ptrace` su macOS non espone `PTRACE_GETSIGINFO`; va preso dall'eccezione Mach. Lavoro diverso, non una copia del fix Linux. |
| **Eventi thread** | macOS | Nessun equivalente di `PTRACE_O_TRACECLONE` implementato. |
| **Canonico del frame pointer** | crate | `RegisterSchema` dice `x29`, `register_context` dice `fp`. Entrambe hanno test: **è una decisione, non un refactoring**. ⚠️ Richiede una scelta dell'utente. |
| **iOS su hardware** | infrastruttura | Non ottenibile su Actions con nessuna configurazione: serve un device fisico e un runner self-hosted. |
| **`pyo3 0.23`** | workspace | Il pin a Python 3.13 rende il build riproducibile ma non risolve: alzarlo richiede l'upgrade di pyo3 su tre crate. |
| **14 file `.bak*`** | `src/` | Copie di backup nel primo commit. Decisione dell'utente. |

**Chiusi nelle iterazioni 541-544**: `ThreadExit` end-to-end su Linux, i test non
isolati della cache PDB, e i quattro difetti di build Unix.

---

## 7. Fronti chiusi con una misura (non ricontrollare)

- `dwarf_cfi` è **pulito** sulla lente "campo oltre la lunghezza dichiarata".
- `item_body` **non è vacuo**: 111 estrazioni, minimo 224 caratteri.
- Nessuna stringa con `//` nei tre backend.
- Nessun metodo manca a un backend: 42/40/40, sole differenze i due lettori PE.
- Tutti i campi di stato MCP (`killed`, `removed`, `enabled`, `detached`…) sono
  **derivati**, non costanti — e dall'iterazione 544 hanno finalmente qualcosa di
  veritiero sotto da cui derivare.
- Tutte le 26 dichiarazioni `"source"` sono corrette.
- Inventario dei `cfg` di piattaforma (544): quelli rimasti hanno tutti il ramo
  di fallback. Da qui in poi la classe è coperta dalla CI.

---

## 8. Lezioni di metodo che governano il lavoro

1. **Un test che si *appende* quando il codice è sbagliato non è un test.**
2. **Un commento che giustifica l'azione non giustifica lo scarto del suo
   esito** — vista 6 volte (536, 537, 538, 540, 542a, 544).
3. **Un'eccezione motivata va ristretta al caso che la motiva.**
4. **Quando un silenzio non si può trasformare in errore, cercare un chiamante
   diverso che possa rispondere** (541: la coda `deferred_exits`).
5. **Test verde + fail-first non bastano** se esiste un'invariante di progetto
   più larga (530).
6. **Leggere il consumatore, non provare varianti del produttore** (528).
7. **Misurare prima di correggere.**
8. **Un guard ancorato a una stringa di firma è fragile** (540).
9. **Una funzione che ritorna `()` non ha dove mettere un fallimento** (540): il
   tipo di ritorno è parte dell'invariante, non una preferenza di stile.
10. **Un numero va ricontrollato quando lo si eredita** (540): «55 moduli,
    69 518 righe» era vero e descriveva il 58% del crate.
11. **Rendere un controllo severo alla cieca è un difetto nuovo** (544): `ESRCH`
    su un detach non è un fallimento, e propagarlo avrebbe fatto fallire
    `detach()` ogni volta che un thread muore.
12. **Un elenco di piattaforme si verifica compilando, non rileggendo** (542-543).
13. **Un job che resta in coda per sempre è peggio di uno che fallisce**: non
    riporta mai, e chi lo aspetta non lo sa.
