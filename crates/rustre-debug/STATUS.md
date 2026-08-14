# STATUS — `rustre-debug`

> **Cruscotto del debugger.** Aggiornato a **ogni iterazione** del loop di
> miglioramento. Ogni numero qui è **misurato**, mai stimato: se una cosa non è
> stata misurata, è scritto che non lo è stata.
>
> Ultimo aggiornamento: **iterazione 539** · 2026-08-14

---

## 1. Semaforo — come siamo messi adesso

| Indicatore | Valore | Note |
|---|---|---|
| **Test Windows** (`rustre-debug --lib`) | **1885 / 1885** ✅ | 0 falliti |
| **Test Linux** (WSL, serial) | **1870 / 1870** ✅ | `--test-threads=1` obbligatorio |
| **Test MCP** (`rustre-mcp-tools --lib`) | **392 / 392** ✅ | superficie utente |
| **macOS x86_64** (`cargo check`) | ✅ 0 errori | ⚠️ compila, **non eseguito** |
| **macOS aarch64** (`cargo check`) | ✅ 0 errori | ⚠️ compila, **non eseguito** |
| **Regressioni aperte** | **0** | nessuna ammessa per regola |

### Copertura per piattaforma — il dato più importante

| | Windows | Linux | macOS |
|---|---|---|---|
| Metodi backend (produzione) | **42** | **40** | **40** |
| Test **live** (processo reale) | **67** | **34** | **0** ⚠️ |
| Esecuzione verificata | ✅ | ✅ | ❌ **mai** |

> ⚠️ **Il limite principale del progetto**: su macOS nulla è mai stato
> *eseguito*. Tutte le correzioni che lo riguardano sono verificate per
> compilazione e per ispezione del sorgente. Per questo esistono i **guard test
> sul sorgente** (§4), che sono la sola rete che copre quel backend.

---

## 2. Dimensioni

| Componente | Righe |
|---|---|
| `rustre-debug` (55 moduli) | **69 518** |
| ├─ `lib.rs` (core + guard test) | 12 001 |
| ├─ `windows_debugger.rs` | 8 309 |
| ├─ `linux_debugger.rs` | 5 323 |
| └─ `macos_debugger.rs` | 4 265 |
| `rustre-mcp-tools` — `tools/debug.rs` | **6 852** |

---

## 3. Cosa è stato corretto — iterazioni 516→539

Legenda: 🐛 bug reale · 🕳 gap chiuso · 🛡 protezione · ❌ ritirato · 📏 misura

| # | Cosa | Tipo | OS | Fail-first |
|---|---|---|---|---|
| 516 | Clamp record su ThreadList e Memory64List | 🐛 | tutti | ✅ |
| 517 | `LC_MAIN` letto oltre il proprio `cmdsize` | 🐛 | macOS | ✅ |
| 518 | `LC_SEGMENT_64` idem → segmento fantasma nell'immagine | 🐛 | macOS | ✅ |
| 519 | Campi `MISC_INFO` letti in sequenza anziché a offset fissi | 🐛 | minidump | ✅ |
| 520 | `ContextFlags` x64 letto a offset 0 (sta a 0x30) → **0 registri** | 🐛 | Windows | ✅ |
| 521 | Ramo i386 assente → dump 32-bit senza registri | 🕳 | Windows | ✅ |
| 522 | `cpsr`/`pstate`: stesso registro, due nomi, invisibile | 🐛 | ARM64 | ✅ |
| 523 | `set()` non riconosceva `fp` come frame pointer | 🐛 | AArch64 | ✅ |
| 524 | SIGSEGV senza indirizzo faultante | 🕳 | Linux | ✅ live |
| 525 | Eventi thread classificati `Unknown` | 🕳 | Windows | ✅ live |
| 526 | Nascita thread rilevata e **ingoiata** | 🕳 | Linux | ⚠️ non ottenuto |
| 527 | *(misura — nessuna consegna)* | 📏 | — | — |
| 528 | Protocollo di resume: evento informativo ≠ thread fermo | 🐛 | Linux | ✅ |
| 529 | Thread morto lasciato in `known_tids` (i tid si riusano) | 🐛 | Linux | ✅ |
| 530 | *(ritirata: due guard test l'hanno bocciata, a ragione)* | ❌ | — | — |
| 531 | Pending breakpoint su libreria non caricata | 🕳 | **tutti e 3** | ✅ ×2 |
| 532 | Guard tri-OS cieco sui metodi mancanti | 🛡 | tutti | ✅ ×2 |
| 533 | `detach` non verificava il ripristino dei `0xCC` | 🐛 | tutti e 3 | ✅ |
| 534 | Disarmo debug register: esito scartato, contabilità svuotata | 🐛 | tutti e 3 | ✅ |
| 535 | `enable_breakpoint`: riarmo watchpoint non verificato | 🐛 | tutti e 3 | ✅ |
| 536 | MCP: «detached again» affermato senza controllo | 🐛 | MCP | ✅ |
| 537 | MCP: `"detached": true` con dr7 forse ancora armato | 🐛 | MCP | ✅ |
| 538 | MCP: «the process was killed» affermato senza controllo | 🐛 | MCP | ✅ |
| 539 | Guard sulle dichiarazioni di provenienza (`"source"`) | 🛡 | MCP | ✅ |

**Totale: 19 difetti/gap corretti, 3 protezioni aggiunte, 1 ritirata, 1 sola misura senza consegna.**

---

## 4. Reti di sicurezza

| Rete | Quantità | A cosa serve |
|---|---|---|
| Test **live** Windows | 67 | processo reale, breakpoint/watchpoint veri |
| Test **live** Linux | 34 | ptrace reale, fixture `pthread` compilate al volo |
| **Guard test sul sorgente** (`lib.rs`) | **246** | l'unica rete che copre **macOS** |
| Guard test MCP | 4 | affermazioni verso l'utente |

**Regola di verifica** (rispettata a ogni iterazione):
Windows + Linux eseguiti · MCP eseguito · entrambi i target Darwin compilati ·
**fail-first misurato** prima di dichiarare un fix.

---

## 5. Difetti aperti — dichiarati, non nascosti

| Cosa | Dove | Perché non è chiuso |
|---|---|---|
| **`rewind_past_own_breakpoint`** | tutti e 3 | Se `set_registers` fallisce il pc resta **dopo** l'int3 e il target esegue in mezzo a un'istruzione, mentre l'evento afferma il contrario. Serve un canale per dire «l'evento è vero ma lo stato no» sul percorso di resume: **lavoro di struttura**. |
| **`ThreadExit` end-to-end** | Linux | L'uscita è **divorata da `ensure_stopped`** (misurato: `waitpid → status=0x0`), che è un comando sincrono senza canale eventi. |
| **Indirizzo faultante** | macOS | `ptrace` su macOS non espone `PTRACE_GETSIGINFO`; va preso dall'eccezione Mach. Lavoro diverso, non una copia del fix Linux. |
| **Eventi thread** | macOS | Nessun equivalente di `PTRACE_O_TRACECLONE` implementato. |
| **Canonico del frame pointer** | crate | `RegisterSchema` dice `x29`, `register_context` dice `fp`. Entrambe hanno test: **è una decisione, non un refactoring**. ⚠️ Richiede una scelta dell'utente. |
| **Esecuzione su macOS** | infrastruttura | Serve un runner reale (GitHub Actions o una macchina Mac). |

---

## 6. Fronti chiusi con una misura (non ricontrollare)

- `dwarf_cfi` è **pulito** sulla lente "campo oltre la lunghezza dichiarata".
- `item_body` **non è vacuo**: 111 estrazioni, minimo 224 caratteri.
- Nessuna stringa con `//` nei tre backend (difetto latente, non attuale).
- Nessun metodo manca a un backend: 42/40/40, sole differenze i due lettori PE.
- **Zero** altri `let _ =` seguiti da un'affermazione di successo (ricerca sistematica).
- Tutti i campi di stato MCP (`killed`, `removed`, `enabled`…) sono **derivati**, non costanti.
- Tutte le 26 dichiarazioni `"source"` sono corrette.

---

## 7. Lezioni di metodo che governano il lavoro

1. **Un test che si *appende* quando il codice è sbagliato non è un test** — nasconde il difetto e avvelena i run successivi.
2. **Un commento che giustifica l'azione non giustifica lo scarto del suo esito** (vista 3 volte: 536, 537, 538).
3. **Un'eccezione motivata va ristretta al caso che la motiva.**
4. **Quando un silenzio non si può trasformare in errore, cercare un chiamante diverso che possa rispondere.**
5. **Test verde + fail-first non bastano** se esiste un'invariante di progetto più larga (530).
6. **Leggere il consumatore, non provare varianti del produttore** (528: tre iterazioni risolte da una lettura).
7. **Misurare prima di correggere** — ha già evitato due volte di trattare casi diversi come uguali.
