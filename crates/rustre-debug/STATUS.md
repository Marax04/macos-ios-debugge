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
> Ultimo aggiornamento: **iterazione 549** · 2026-08-15
> **Questa è una riscrittura completa** (548 = 4×137). Prossima: iterazione 552.

---

## 1. Il traguardo, e cosa è costato scoprirlo

**macOS Apple Silicon: job CI `completed: success`.** Non solo la suite del
debugger — l'intero job, incluso `Test rustre-mcp-tools`:

```
6. Build (release) ......... success
7. Test (release, serial) .. success
8. Test rustre-mcp-tools ... success
```

Il backend macOS e la superficie MCP sono verificati su hardware Apple reale. Era
il limite dichiarato del progetto da 539 iterazioni.

Non è stato chiuso da una correzione. È stato chiuso scoprendo che il repo **non
aveva nessun commit e nessun remote**, quindi il workflow macOS esisteva e non
era mai partito: «macOS non è mai stato eseguito» non era un difetto da
correggere, era una conseguenza aritmetica.

---

## 2. Semaforo

| Indicatore | Valore | Note |
|---|---|---|
| **Test Windows** (fuori da `ios::`) | **1924 / 1924** ✅ | rimisurato al 549 |
| **Test Windows** (totale) | 1924 + 8 rossi in `ios::` | ⚠️ i rossi sono i **fail-first in corso** degli agenti del workflow iOS round 2, rossi per costruzione |
| **Test Linux** (WSL, seriale) | 1904 / 1904 ✅ | misurato al **547** |
| **Test MCP** | **392 / 392** ✅ | rimisurato al 549 |
| **macOS x86_64** (`cargo check`) | ⚠️ **bloccato** | 5 errori in `src/ios/mock_debugserver.rs`, file in mezzo a una modifica del workflow parallelo — **non** attribuibili al lavoro di questi round |
| **macOS aarch64** (`cargo check`) | ⚠️ stessa causa | |
| **macOS ARM su CI** | ✅ **success** | job intero, hardware reale |
| **iOS Simulator su CI** | **1828 / 1833** | i 5 rossi corretti al 549, non ancora ri-eseguiti |
| **`aarch64-pc-windows-msvc`** | ❓ **non misurato** | `libsqlite3-sys` richiede un cross-compiler C assente qui |

### Copertura per piattaforma

| | Windows x64 | Linux x64 | macOS ARM | macOS Intel | iOS |
|---|---|---|---|---|---|
| Compila | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Eseguito** | ✅ | ✅ | ✅ **CI** | 🟡 in corso | 🟡 Simulator |
| Test live (processo reale) | 67 ¹ | 34 ¹ | 0 | 0 | 0 |
| Breakpoint software su ARM64 | — | ❌ rifiutato | ❌ rifiutato | ❌ rifiutato | — |

¹ non rimisurato in questo consolidamento.

---

## 3. Dimensioni

Rimisurate al 549.

| Componente | File | Righe |
|---|---|---|
| `src/*.rs` (primo livello) | 55 | **70 784** |
| ├─ `lib.rs` | | 12 354 |
| ├─ `windows_debugger.rs` | | 8 396 |
| ├─ `linux_debugger.rs` | | 5 507 |
| └─ `macos_debugger.rs` | | 4 557 |
| `src/ios/` (**537** test) | 17 | **32 762** |
| `src/codeview/` | 15 | **19 539** |
| **`rustre-debug` totale** | **87** | **123 085** |
| `build.rs` (nuovo al 549) | 1 | 76 |

Il backend iOS è cresciuto da 30 739 a 32 762 righe e da 502 a **537 test** in due
giri di workflow.

---

## 4. Iterazioni 540-549

### 516→540: compresse
19 difetti/gap, 3 protezioni, 1 ritirata, 1 misura senza consegna.

### 540 — il rewind del breakpoint fallito
`rewind_past_own_breakpoint` scartava **due** fallimenti e il chiamante riceveva
`Ok(Breakpoint{..})`: vero su cosa è successo, falso sullo stato lasciato.
Riprendendo, il target riparte *dentro* un'istruzione. Le tre funzioni erano
identiche byte-per-byte. Firma → `Result`, sei chiamanti aggiornati.

### 541 — `ThreadExit`: un ramo corretto senza produttore
`ensure_stopped` faceva `waitpid`, **consumava** l'uscita e usciva. Il fail-first
era già scritto in negativo: il test live rinunciava deliberatamente ad
asserirlo. Fix: coda `deferred_exits`, consegnata **prima** di riprendere.

### 542 — tre difetti, uno per piattaforma nascosta
Restore scartato (tutti e 3) · iOS caduto dalla fine di una lista `#[cfg]`
(`error[E0423]`, **il crate non compilava**) · `rustre-ttd-recorder` mai
compilato su Linux (8 `const fn` col corpo `cfg(linux)`, e sotto
`ptrace::write` col terzo argomento mistipizzato).

### 543 — capacità mancante che rendeva i test non isolati
`RUSTRE_PDB_CACHE` aggiunto; `call_tool` de-gated invece che gatare ~30 smoke
test MCP sulla piattaforma che stiamo verificando.

### 544 — `detach` rispondeva con una costante
Tutti e tre scartavano ogni ritorno e rispondevano `Ack(Ok(()))`. Su Windows un
processo che resta debuggato viene **ucciso** quando il debugger esce. `ESRCH` è
perdonato: un target già andato non ha più nulla da cui staccarsi.

### 545 — il guard che mancava, dimostrato
Guard sui port Mach esteso a `read_thread_state`/`write_thread_state`, con
l'invariante sull'**ordine** (`release_port` prima di ogni `return Err`) e non
sulla presenza. Provato reintroducendo il difetto e vedendolo diventare rosso.

### 546 — i backend ptrace non vedevano le proprie trappole su arm64
Entrambi scrivevano l'assunzione x86 inline: PC meno **uno**, cerca `0xCC`. Su
AArch64 la trappola è `BRK #0` da **quattro** byte e il PC riportato è
l'indirizzo *di* essa. Il predicato non poteva mai essere vero, quindi ogni hit
di breakpoint veniva classificato come single step. Un guard preesistente
**pretendeva il letterale `0xCC`**: il guard portava il difetto che doveva
prevenire. Aggiunto `arch_breakpoint::host() -> Option<BpArch>`.

### 547 — un guard leggeva i sorgenti a runtime
Percorso relativo, funziona solo se il CWD è la root del crate. Non lo è sotto
`simctl spawn`. Ora `include_str!`.

### 548 — salvava 1 byte e ne scriveva 4
```rust
let original = self.read_memory(addr, 1).await?;                       // 1
let n = self.write_memory_raw(addr, crate::host_trap_bytes()).await?;  // 4 su arm64
```
`remove_breakpoint` ripristina ciò che è stato salvato: su ARM64 ripristinerebbe
un byte e lascerebbe **tre byte di `BRK`** nel flusso di istruzioni — corruzione
permanente di un processo che l'utente aveva chiesto solo di osservare. È
letteralmente il fallimento che la doc di `arch_breakpoint::trap_len` descrive.
Aggiunto anche `require_full_read`, gemello mancante di `require_full_write`:
una lettura corta darebbe la stessa corruzione dall'altra porta.

**Non fatto di proposito**: rimuovere `X86_TRAP_BYTE_IS_VALID_HERE`. Sembrava
stantio — l'impianto deriva già i byte dall'architettura — ma era l'ultima difesa
davanti a *questo* difetto. Toglierlo sarebbe stato il «fix che crede di aver
sistemato più di quanto ha», contro cui il guard di quella costante mette
esplicitamente in guardia.

### 549 — i guard non potevano girare fuori dal repository
`production_sources()` camminava `src/` con `read_dir` a runtime: cinque guard
falliti in blocco alla prima esecuzione su una triple Apple, perché la sandbox
del simulatore non ha un repository a nessun percorso. `include_str!` da solo non
bastava — quei guard devono coprire **ogni** file, e una lista scritta a mano
diventa stantia al primo file aggiunto, cioè un guard che smette silenziosamente
di coprire: peggio di nessun guard, perché si legge come copertura. Aggiunto un
`build.rs` che enumera a compile time, con `rerun-if-changed` sulla **directory**
oltre che sui file.

---

## 5. La classe che ha dominato questi round

Sei difetti distinti, una sola causa: **il workspace è stato scritto e verificato
solo su Windows x86 per tutta la sua vita**, quindi ogni elenco di piattaforme
scritto a mano e ogni assunzione di architettura è rimasta non verificata per
anni.

| Difetto | Invisibile su |
|---|---|
| `pyo3` vs Python del runner | Windows |
| `fuser` dipendenza obbligatoria | Windows |
| `#[path="../x.rs"]` in modulo inline | Windows (normalizza il `..` lessicalmente) |
| `const fn` con corpo `cfg(linux)` | Windows |
| PC-1 e `0xCC` nei classificatori | x86 |
| salva 1 byte, ne scrive 4 | x86 |

**539 iterazioni di ispezione del sorgente non hanno trovato ciò che un solo run
di CI ha trovato in venti minuti**, e non per distrazione: sono difetti
strutturalmente invisibili alla macchina di sviluppo.

E la CI ha trovato anche **due difetti del workflow che l'aveva scritta**: i test
del simulatore giravano prima del boot, e `macos-13` è ritirato — l'etichetta
viene accettata alla lettura e poi mai schedulata, che è peggio di un fallimento
perché non riporta mai nulla.

---

## 6. Il fronte Apple: due giri di workflow

**Giro 1** — audit su 16 superfici, ogni segnalazione a **tre scettici
indipendenti col compito di confutarla**: 34 trovate, **24 sopravvissute, 10
buttate**. Poi un agente per file, ognuno rivisto da un avversario: **26 difetti
chiusi su 13 file, +2200 righe**.

Due file bocciati come «dubbio», e i revisori avevano ragione su entrambi:
- i guard di `macos_debugger.rs` vivevano solo in uno scratchpad, fuori da
  `cargo test` → nessuna protezione permanente (chiuso al **545**);
- `arm64.rs` asseriva `decode(retaa) == Return { reg: 31 }`, cristallizzando un
  registro **sbagliato** come comportamento atteso: `Rn` è obbligato a `11111`
  ma il ritorno passa da **x30**, e `11111` lì è `xzr` (corretto nel commit
  57b8fe2);
- una motivazione tecnica esattamente **rovesciata** (`is_some_and` *consuma*
  l'`Option`) — corretta al 546.

**Giro 2** — in corso: sei lenti su ciò che il primo giro non poteva vedere
(regressioni introdotte dai fix stessi, conformità RSP contro la specifica, dove
il mock è più permissivo del `debugserver` vero, maschere PAC e tagged pointer).

---

## 7. Difetti aperti — dichiarati, non nascosti

| Cosa | Dove | Perché non è chiuso |
|---|---|---|
| **Breakpoint software su ARM64** | tutti e 3 | Rifiutati da `X86_TRAP_BYTE_IS_VALID_HERE`. Il 548 ha rimosso il difetto che rendeva il rifiuto necessario; resta da portare `read_regs`/`regs_to_register_set` su Linux (usa ancora `user_regs_struct::rip`, 11 occorrenze) prima di poterlo togliere. macOS è già portato (`thread_pc` è cfg'd). |
| **macOS Intel eseguito** | CI | `macos-15-intel` schedula e gira dal 544; il primo risultato **non è ancora stato letto**. |
| **Indirizzo faultante** | macOS | Va preso dall'eccezione Mach: `ptrace` su macOS non espone `PTRACE_GETSIGINFO`. |
| **Eventi thread** | macOS | Nessun equivalente di `PTRACE_O_TRACECLONE`. |
| **Canonico del frame pointer** | crate | `x29` vs `fp`, entrambe con test. ⚠️ **decisione dell'utente**, non un refactoring. |
| **iOS su hardware** | infrastruttura | Non ottenibile su Actions: serve un device fisico e un runner self-hosted. |
| **`pyo3 0.23`** | workspace | Il pin a 3.13 rende il build riproducibile; alzarlo richiede l'upgrade su tre crate. |
| **14 file `.bak*`** | `src/` | Decisione dell'utente. |

---

## 8. Lezioni di metodo

1. **Un test che si *appende* quando il codice è sbagliato non è un test.**
2. **Un commento che giustifica l'azione non giustifica lo scarto del suo esito**
   — vista 6 volte.
3. **Un'eccezione motivata va ristretta al caso che la motiva.**
4. **Quando un silenzio non si può trasformare in errore, cercare un chiamante
   diverso che possa rispondere** (541).
5. **Leggere il consumatore, non provare varianti del produttore** (528).
6. **Misurare prima di correggere.**
7. **Un guard ancorato a una stringa è fragile** (540, 546).
8. **Una funzione che ritorna `()` non ha dove mettere un fallimento** (540).
9. **Un numero va ricontrollato quando lo si eredita** (540).
10. **Rendere un controllo severo alla cieca è un difetto nuovo** (544): `ESRCH`
    su un detach non è un fallimento.
11. **Un elenco di piattaforme si verifica compilando, non rileggendo** (542-546).
12. **Un job che resta in coda per sempre è peggio di uno che fallisce**: non
    riporta mai, e chi lo aspetta non lo sa.
13. **Un guard può portare il difetto che dovrebbe prevenire** (546): pretendeva
    il letterale `0xCC`.
14. **Quando una difesa sembra stantia, cercare cosa sta difendendo** (548): il
    rifiuto ARM64 non era obsoleto, era l'ultima cosa tra il debugger e la
    corruzione permanente del target.
15. **Un guard che si salta non è un guard** (549): l'alternativa comoda —
    saltare quando l'albero non c'è — si legge come copertura.
