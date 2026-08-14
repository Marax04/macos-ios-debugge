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
> Ultimo aggiornamento: **iterazione 540** · 2026-08-14
> **Questa è una riscrittura completa** (540 = 4×135). Prossima: iterazione 544.

---

## 1. Semaforo — come siamo messi adesso

Tutto rimisurato oggi, in questa iterazione.

| Indicatore | Valore | Note |
|---|---|---|
| **Test Windows** (`rustre-debug --lib`) | **1887 / 1887** ✅ | 0 falliti |
| **Test Linux** (WSL, seriale) | **1872 / 1872** ✅ | `--test-threads=1` obbligatorio |
| **Test MCP** (`rustre-mcp-tools --lib`) | **392 / 392** ✅ | superficie utente |
| **macOS x86_64** (`cargo check`) | ✅ 0 errori | 68 warning, preesistenti |
| **macOS aarch64** (`cargo check`) | ✅ 0 errori | build in 10m 57s |
| **Regressioni aperte** | **0** | nessuna ammessa per regola |

### Copertura per piattaforma — il dato più importante

| | Windows | Linux | macOS | iOS |
|---|---|---|---|---|
| Test **live** (processo reale) | **67** ¹ | **34** ¹ | **0** ⚠️ | **0** |
| Esecuzione verificata | ✅ | ✅ | ❌ mai | ❌ mai |
| Compilazione verificata | ✅ | ✅ | ✅ ×2 arch | ❌ **mai** ² |

¹ non rimisurato in questa iterazione — riportato dal consolidamento precedente.
² misurato oggi: `grep -r "apple-ios"` su tutto il repo non trova **nulla**. iOS
è un backend che non è mai stato un *target di build*.

---

## 2. Il cambiamento strutturale di oggi: la CI esiste

Fino a stamattina il repo **non aveva nessun commit e nessun remote**
(`git rev-list --count HEAD` → errore). Il workflow macOS era scritto ma non era
mai partito, quindi «macOS non è mai stato eseguito» non era un difetto da
correggere: era una conseguenza aritmetica.

Oggi: primo commit, remote `github.com/Marax04/macos-ios-debugge`, push su
`main`. Il ramo è stato rinominato da `master` — il workflow si attiva su
`branches: [main]`, quindi il push sarebbe stato inerte.

Prima di poter pushare sono stati esclusi dal tree, perché GitHub rifiuta ogni
file oltre 100 MB: `tests/mcios/` (`BaseSystem.dmg` da solo **752 MB**), le
immagini `.qcow2`, e i protettori commerciali in `tools/*.zip` (software di
terzi, non ridistribuibile).

**Aggiunto oggi anche il job iOS**, con quello che può e non può provare scritto
nel workflow stesso: *può* provare che `src/ios` compila per
`aarch64-apple-ios` e `aarch64-apple-ios-sim` (mai fatto prima) e che un
`debugserver` reale esiste; **non può** dire nulla su iOS, perché il Simulator
gira sul kernel macOS dell'host. La parte che avvia il simulatore è l'unica del
workflow con `continue-on-error`, così una sua fragilità non può far passare per
verde un fallimento di compilazione o di test.

> ⚠️ **Stato reale al momento della scrittura**: il push è avvenuto, il primo run
> della CI **non è ancora stato letto**. Finché non lo è, macOS resta a
> esecuzione **non verificata** — la riga qui sopra dice che la CI esiste, non
> che è passata.

---

## 3. Dimensioni

Rimisurate oggi. La tabella precedente contava solo `src/*.rs` e dichiarava
«69 518 righe, 55 moduli»: **descriveva il 58% del crate**, omettendo
interamente `src/ios` e `src/codeview`.

| Componente | File | Righe |
|---|---|---|
| `src/*.rs` (primo livello) | 55 | **69 675** |
| ├─ `lib.rs` (core + guard test) | | 12 086 |
| ├─ `windows_debugger.rs` | | 8 333 |
| ├─ `linux_debugger.rs` | | 5 347 |
| └─ `macos_debugger.rs` | | 4 289 |
| `src/ios/` | 17 | **30 739** |
| `src/codeview/` | 15 | **19 539** |
| **`rustre-debug` totale** | **87** | **119 953** |
| `rustre-mcp-tools` — `tools/debug.rs` | 1 | 6 852 |

**Da ripulire**: 14 file `.bak*` in `src/`. Non sono compilati (fuori
dall'albero dei moduli), quindi sono copie di backup, non funzionalità non
cablata — ma sono finiti nel primo commit.

---

## 4. Reti di sicurezza

| Rete | Quantità | A cosa serve |
|---|---|---|
| Test **live** Windows | 67 ¹ | processo reale, breakpoint/watchpoint veri |
| Test **live** Linux | 34 ¹ | ptrace reale, fixture `pthread` compilate al volo |
| **Guard test sul sorgente** (`lib.rs`) | **248** ² | l'unica rete che copre **macOS** |
| Test in `src/ios/` | **502** | misurato oggi; girano su **ogni** host |
| Guard test MCP | 4 ¹ | affermazioni verso l'utente |

¹ non rimisurato in questa iterazione.
² 246 del consolidamento precedente + i 2 aggiunti oggi. Il metodo di conteggio
originale non è stato riprodotto: `lib.rs` contiene **249** `#[test]` misurati,
un sovrainsieme che include test non-guard.

I 502 test iOS girano su Windows e Linux per una scelta dichiarata in
`src/ios/mod.rs`: *nothing is gated on `cfg(target_os = "macos")`* — la
conoscenza Apple (layout Mach-O, compact-unwind, convenzioni ARM64) è aritmetica
su byte e registri, e solo l'accesso vero alle syscall sta dietro un trait.

**Regola di verifica** (rispettata a ogni iterazione):
Windows + Linux eseguiti · MCP eseguito · entrambi i target Darwin compilati ·
**fail-first misurato** prima di dichiarare un fix.

---

## 5. Iterazioni 516→540

Le 24 iterazioni precedenti sono compresse: **19 difetti/gap corretti, 3
protezioni aggiunte, 1 ritirata** (bocciata da due guard test, a ragione), **1
misura senza consegna**. Coprivano minidump, contesto x64/i386, registri ARM64,
eventi thread Linux/Windows, pending breakpoint tri-OS, e quattro affermazioni
MCP fatte senza controllo.

### Iterazione 540 — dettaglio

**Difetto**: il primo di §6 nel consolidamento precedente, aperto da tempo e
marcato «lavoro di struttura».

La CPU porta il PC oltre l'`int3` eseguito *prima* di sollevare l'eccezione, quindi
dopo uno dei nostri breakpoint il PC va riportato all'indirizzo del breakpoint
prima di poter riprendere. `rewind_past_own_breakpoint` leggeva i registri sotto
`if let Ok(..)` e li riscriveva sotto `let _ =`: **entrambi i fallimenti erano
scartati**, e il chiamante riceveva comunque `Ok(Breakpoint { address })` — un
evento *vero su cosa è successo e falso sullo stato che ha lasciato*. Riprendendo,
il target riparte **dentro** un'istruzione: esecuzione arbitraria, non una
risposta approssimata.

Le tre funzioni erano **byte-per-byte identiche** (verificato con `diff`), quindi
il difetto era identico su Windows, Linux e macOS.

**Fix**: firma `-> Result<(), DebugError>`, propagazione di entrambi i
fallimenti, e i **sei** chiamanti (`single_step_raw` e `continue_execution` per
backend) che convertono un rewind fallito in errore invece di restituire
l'evento. Il conteggio dell'hit resta *prima* del rewind: il breakpoint è
scattato davvero, e resta vero anche quando il rewind che segue non lo è.

**Fail-first**: ✅ misurato, due guard rossi su tutti e tre i backend prima di
toccare il codice (`windows:773: the rewind's result is discarded at the call
site`). Il secondo guard esiste separato perché dare un tipo di ritorno alla
funzione e poi chiamarla come istruzione nuda ripristinerebbe il difetto un
livello più fuori, con il primo guard verde.

**Effetto collaterale gestito**: due guard preesistenti ancoravano la vecchia
firma come stringa e si sono rotti per un motivo estraneo a ciò che controllano.
Le loro àncore sono ora indipendenti dalla firma.

**MCP**: nessuna modifica necessaria, *verificato invece che assunto* — tutti i
siti utente (`debug.rs:874, 915, 1551, 2702, 2750`) propagano già con
`map_err(..)?`, quindi il fallimento arriva all'utente come errore e non come
falso «fermato al breakpoint».

---

## 6. Difetti aperti — dichiarati, non nascosti

| Cosa | Dove | Perché non è chiuso |
|---|---|---|
| **Primo run CI non letto** | infrastruttura | Il push è avvenuto oggi; finché il risultato non è letto, «macOS eseguito» **non è ancora vero**. |
| **`ThreadExit` end-to-end** | Linux | L'uscita è **divorata da `ensure_stopped`** (misurato: `waitpid → status=0x0`), che è un comando sincrono senza canale eventi. |
| **Indirizzo faultante** | macOS | `ptrace` su macOS non espone `PTRACE_GETSIGINFO`; va preso dall'eccezione Mach. Lavoro diverso, non una copia del fix Linux. |
| **Eventi thread** | macOS | Nessun equivalente di `PTRACE_O_TRACECLONE` implementato. |
| **Canonico del frame pointer** | crate | `RegisterSchema` dice `x29`, `register_context` dice `fp`. Entrambe hanno test: **è una decisione, non un refactoring**. ⚠️ Richiede una scelta dell'utente. |
| **iOS su hardware** | infrastruttura | Non ottenibile su Actions con nessuna configurazione: serve un device fisico e un runner self-hosted. |
| **14 file `.bak*`** | `src/` | Copie di backup entrate nel primo commit. Rimozione non fatta: è una decisione dell'utente. |

**Chiuso in questa iterazione**: `rewind_past_own_breakpoint` (era il primo della
tabella).

---

## 7. Fronti chiusi con una misura (non ricontrollare)

- `dwarf_cfi` è **pulito** sulla lente "campo oltre la lunghezza dichiarata".
- `item_body` **non è vacuo**: 111 estrazioni, minimo 224 caratteri.
- Nessuna stringa con `//` nei tre backend.
- Nessun metodo manca a un backend: 42/40/40, sole differenze i due lettori PE.
- **Zero** altri `let _ =` seguiti da un'affermazione di successo *nei tre
  backend* — ricerca sistematica del consolidamento precedente. L'ultimo,
  in `rewind_past_own_breakpoint`, è chiuso oggi: era sfuggito perché il `let _ =`
  non era seguito da un'affermazione ma da **una funzione che ritornava `()`**.
- Tutti i campi di stato MCP (`killed`, `removed`, `enabled`…) sono **derivati**.
- Tutte le 26 dichiarazioni `"source"` sono corrette.

---

## 8. Lezioni di metodo che governano il lavoro

1. **Un test che si *appende* quando il codice è sbagliato non è un test.**
2. **Un commento che giustifica l'azione non giustifica lo scarto del suo
   esito** — vista 4 volte (536, 537, 538, **540**).
3. **Un'eccezione motivata va ristretta al caso che la motiva.**
4. **Quando un silenzio non si può trasformare in errore, cercare un chiamante
   diverso che possa rispondere.**
5. **Test verde + fail-first non bastano** se esiste un'invariante di progetto
   più larga (530).
6. **Leggere il consumatore, non provare varianti del produttore** (528).
7. **Misurare prima di correggere.**
8. **Un guard ancorato a una stringa di firma è fragile** (540): si rompe quando
   la firma cambia, per un motivo che non c'entra con ciò che controlla.
9. **Una funzione che ritorna `()` non ha dove mettere un fallimento** (540): il
   tipo di ritorno è parte dell'invariante, non una preferenza di stile.
10. **Un numero va ricontrollato quando lo si eredita** (540): «55 moduli, 69 518
    righe» era vero e descriveva il 58% del crate.
