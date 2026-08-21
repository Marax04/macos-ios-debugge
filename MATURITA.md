# RustRE — livello di maturità delle 189 crate

**Valutazione misurata, non impressionistica.**

- Data: 2026-08-21
- Ambito: tutte le crate del workspace **tranne `rustre-gui`** (esclusa su richiesta)
- Metodo: sei segnali misurati su ogni crate, più verifica **leggendo il codice** di un campione di ogni livello. Dove la misura e la lettura hanno divergito, ha vinto la lettura, ed è annotato.

---

## 0. Come leggere questo documento

Il primo tentativo di classificazione produceva un solo punteggio, e **sbagliava**. Metteva `rustre-loader-registry` in fondo (4/14) perché è di 215 righe — mentre leggendolo si scopre che contiene 13 adattatori di formato ed è **completo**. Piccolo non vuol dire immaturo.

L'errore era concettuale: un punteggio unico confonde due cose ortogonali.

> **Quanto è fatto bene il codice** e **quanto è collegato al resto** sono domande diverse, e in questo repository hanno risposte molto diverse.

Il documento usa quindi tre assi separati:

| Asse | Cosa misura | Scala |
|---|---|---|
| **ST — Struttura** | ampiezza dell'API, modularità, lavoro su byte reali, test con oracolo, onestà (nessuna funzione che fabbrica, errori tipizzati) | 0-6 |
| **IG — Integrazione** | dentro la chiusura del decompilatore (l'unica pipeline con metriche), avere dipendenti, essere raggiungibile da MCP | 0-4 |
| **Igiene** | densità di warning clippy per 1000 righe: **A** <2, **B** <6, **C** <12, **D** ≥12 | A-D |

L'igiene è **riportata a parte e non entra nel livello**, per una ragione precisa: al momento della misura tre agenti la stanno riparando attivamente, quindi è l'unico dei tre assi che si muove sotto i piedi. Classificare su un numero in movimento avrebbe prodotto un documento sbagliato entro un'ora.

---

## 1. Il risultato in una tabella

| Livello | Crate | Che cosa significa |
|---|---:|---|
| **0 — Composizione** | 26 | Facciate e registry. Vanno giudicate sul fatto di essere complete, non sulla dimensione. |
| **1 — Enterprise** | 27 | Implementazione ampia **e** integrata in una pipeline misurata. |
| **2 — Avanzato ma spento** | 81 | Implementazione da livello enterprise, **nessuna pipeline la esercita**. |
| **3 — Completo ma isolato** | 16 | Come sopra, ma nemmeno un dipendente: nessuno le chiama. |
| **4 — Intermedio esposto** | 2 | Raggiungibili dall'utente, implementazione più sottile della media. |
| **5 — Intermedio** | 23 | Struttura parziale, integrazione parziale. |
| **6 — Indietro** | 14 | Sottili in entrambi i sensi. |

**Il dato che conta non è la cima, è il centro.** 81 crate su 189 — il 43% — hanno struttura da livello enterprise e **nessuna pipeline che le esercita**. Non è un problema di qualità del codice: è un problema di cablaggio, ed è lo stesso che questa sessione ha già trovato tre volte (i 28 tool SPARC, i 22 tool dietro due funzioni mai chiamate, i 19 backend di architettura mai installati).

---

## 2. Livello 1 — ENTERPRISE (27)

Implementazione ampia **e** dentro una pipeline che qualcuno misura. Sono, quasi senza eccezioni, la catena del decompilatore più l'infrastruttura di base.

| Crate | ST | IG | igiene | pub fn | moduli | kloc |
|---|:-:|:-:|:-:|---:|---:|---:|
| `rustre-core` | 6 | 4 | A | 811 | 27 | 27.6 |
| `rustre-decompiler` | 6 | 4 | A | 657 | 38 | 79.9 |
| `rustre-il-lift` | 6 | 4 | A | 967 | 39 | 88.6 |
| `rustre-analysis-xref` | 6 | 4 | A | 539 | 21 | 19.9 |
| `rustre-symbols` | 6 | 4 | A | 493 | 20 | 22.2 |
| `rustre-decompiler-type` | 6 | 4 | A | 476 | 17 | 16.4 |
| `rustre-events` | 6 | 4 | A | 472 | 11 | 15.6 |
| `rustre-analysis` | 6 | 4 | A | 460 | 15 | 16.6 |
| `rustre-analysis-dataflow` | 6 | 4 | A | 382 | 20 | 23.7 |
| `rustre-flirt-apply` | 6 | 4 | A | 361 | 26 | 20.3 |
| `rustre-analysis-type` | 6 | 4 | A | 354 | 17 | 20.5 |
| `rustre-flirt` | 6 | 4 | A | 349 | 21 | 16.5 |
| `rustre-analysis-vsa` | 6 | 4 | A | 346 | 11 | 19.4 |
| `rustre-flirt-gen` | 6 | 4 | A | 316 | 24 | 17.7 |
| `rustre-demangle` | 6 | 4 | A | 313 | 26 | 26.1 |
| `rustre-il-passes` | 6 | 4 | A | 287 | 14 | 22.4 |
| `rustre-decompiler-cfs` | 6 | 4 | A | 285 | 11 | 17.5 |
| `rustre-decompiler-c` | 6 | 4 | A | 277 | 14 | 15.4 |
| `rustre-analysis-fn` | 6 | 4 | A | 270 | 22 | 19.8 |
| `rustre-symbols-pdb` | 6 | 4 | A | 256 | 21 | 17.5 |
| `rustre-il-llil` | 5 | 4 | A | 366 | 12 | 21.6 |
| `rustre-analysis-callconv` | 5 | 4 | B | 296 | 15 | 18.7 |
| `rustre-loader-elf` | 5 | 4 | A | 269 | 22 | 21.3 |
| `rustre-loader-pe` | 5 | 4 | A | 243 | 21 | 18.1 |
| `rustre-decompiler-expr` | 5 | 4 | A | 209 | 12 | 16.0 |
| `rustre-arch-x86` | 5 | 4 | A | 134 | 20 | 36.9 |
| `rustre-analysis-cfg` | 5 | 4 | B | 347 | 25 | 25.4 |

### Verificato leggendo, non dedotto

**`rustre-flirt-gen`** è il caso migliore del repository. Non "genera pattern": scrive il formato **`IDASGN` reale**, con CRC16 sulle porzioni stabili, mascheramento delle rilocazioni e gestione delle foglie ambigue come fa FLIRT vero (`coff_archive.rs` — la stringa `b"IDASGN"` è asserita in un test). Un parser ELF minimale e un library builder con deduplica completano il quadro. Questo è lavoro da prodotto.

**`rustre-arch-x86`** ha solo 134 funzioni pubbliche su 36.9k righe: il rapporto più basso della categoria. Non è un difetto — è un decoder, la sua superficie è piccola e la sua profondità enorme (`lift.rs` da solo supera le 15k righe).

**`rustre-decompiler`** è l'unica crate del repository con **cinque metriche indipendenti** con oracoli diversi (ricompilabilità, arità contro prototipi pubblicati, coerenza cross-build, comportamento eseguito a fianco dell'originale, simboli irrisolti). È il solo punto in cui il progetto può accorgersi di essere sbagliato.

---

## 3. Livello 2 — AVANZATO MA SPENTO (81)

**È il gruppo più numeroso e il vero risultato di questa analisi.**

Hanno struttura indistinguibile da quella enterprise — 200-600 funzioni pubbliche, 11-26 moduli, 15-20k righe, test a oracolo, errori tipizzati — e **nessuna pipeline misurata le esercita**. Hanno dipendenti e sono raggiungibili da MCP, ma niente le mette alla prova su un corpus.

Campione con struttura piena (ST=6):

`rustre-adb`, `rustre-agent-llm`, `rustre-deobf-smc`, `rustre-diff`, `rustre-emu`,
`rustre-forensics-mem`, `rustre-hex-pattern`, `rustre-loader-macho`, `rustre-loader-dotnet`,
`rustre-mobile-dyld`, `rustre-net-dissect`, `rustre-sandbox-report`, `rustre-symbols-dwarf`,
`rustre-trace-coverage`, `rustre-ttd-replay`, `rustre-yara-engine`, `rustre-ti-vt`, …

### Perché conta

Una crate qui può essere perfetta o completamente sbagliata **e non c'è modo di distinguerlo**, perché nessuna misura la osserva. Questa sessione ne ha avuta la dimostrazione diretta:

> Il parser Lua 5.1/5.2 di `rustre-loader-lua` **non poteva parsare bytecode `luac` autentico**: non leggeva il campo `nups` (spostando di un byte tutto ciò che segue) e leggeva le lunghezze delle stringhe come `int` invece di `size_t`. Il difetto è sopravvissuto a 428 test verdi, perché **le uniche fixture di test erano costruite con lo stesso layout sbagliato**.

Quello è il rischio caratteristico di questo livello: non codice povero, ma codice **non confutabile**.

---

## 4. Livello 3 — COMPLETO MA ISOLATO (16)

Come il livello 2, ma senza nemmeno un dipendente. Nessuno le chiama, in tutto il workspace.

| Crate | pub fn | moduli | test | Cosa contiene davvero (letto) |
|---|---:|---:|---:|---|
| `rustre-symb-taint` | 585 | 17 | 402 | motore di taint completo: sorgenti a bitmask, stato per registro/memoria, funzioni di trasferimento LLIL, rilevamento dei sink pericolosi, inter-procedurale |
| `rustre-triage-yara` | 387 | 18 | 362 | motore di regole per il triage su dati binari grezzi |
| `rustre-symbols-codeview` | 278 | 14 | 452 | CodeView 4.0/7.0: `S_PUB32`, `S_LPROC32`, `S_GPROC32`, `S_GDATA32`, `S_LOCAL`, `S_REGREL32`, `S_COMPILE3`, `S_THUNK32` |
| `rustre-sandbox-extract`, `rustre-sandbox-monitor`, `rustre-ti-correlate`, `rustre-crypto-oracle`, `rustre-crypto-whitebox`, `rustre-emu-shellcode`, `rustre-plugin-host`, … | | | | |

**`rustre-symbols-codeview` merita una nota**: è isolata, ma `rustre-debug` contiene un proprio `codeview/codeview_parser.rs`. Due implementazioni dello stesso formato, una raggiungibile e una no.

Questi non sono crate da completare. Sono crate da **collegare**.

---

## 5. Livelli 4-6 — dove serve davvero lavoro

### 4 — Intermedio esposto (2)

| Crate | ST | IG | Nota |
|---|:-:|:-:|---|
| `rustre-pe-tools` | 4 | 4 | 227 funzioni, 16 moduli: struttura buona, manca l'oracolo |
| `rustre-knowledge` | 4 | 3 | 106 funzioni, 4.1k: è il P4 della specifica (knowledge graph persistente), ed è sottile rispetto a quel ruolo |

`rustre-knowledge` è il caso da guardare per primo: `info.txt` §34 gli assegna il grafo di conoscenza persistente con event sourcing, cioè uno dei cinque principi non negoziabili, e sono 4.1k righe.

### 6 — Indietro (14)

Va letto con attenzione, perché **due voci su quattordici sono artefatti della misura**:

| Crate | ST | IG | Verdetto reale |
|---|:-:|:-:|---|
| `rustre-analysis-typerecov` | 2 | 4 | ⚠ **non è indietro.** Letto: è una pipeline vera in tre stadi — generatore di vincoli → unificatore union-find → recupero delle struct. È *compatta* (4.9k), non povera. La misura penalizza la concisione. |
| `rustre-db` | 2 | 4 | 3.4k, 84 funzioni; sottile per essere il livello di persistenza |
| `rustre-arch-mips` | 2 | 2 | dichiara "MIPS I/II/III/IV/32r2/64 completo"; la decodifica reale c'è (70 riferimenti a opcode/byte order), ma modularità bassa (7 moduli) e igiene D |
| `rustre-arch-arm`, `rustre-arch-riscv` | 2 | 2 | stessa forma: decoder reali, struttura piatta |
| `rustre-syscalls-linux` | 2 | 2 | 231 funzioni ma 7 moduli: è essenzialmente una tabella, il che per un database di syscall è corretto |
| `rustre-dotnet-decompile` | 1 | 2 | 223 funzioni, 6 moduli. Questa sessione ha trovato che `decompile_async` **fallisce su assembly reali**: Roslyn emette `brfalse`/`bne.un` per state machine piccole, non una `switch` table, e la fixture ne emetteva sempre una — quindi ogni test passava contro una forma che il compilatore non produce |
| `rustre-plugin-lua`, `rustre-plugin-native`, `rustre-plugin-python`, `rustre-plugin-loader` | 1 | 0-2 | 0.8-2.3k ciascuna: il sottosistema plugin è il più sottile del repository, ed è il principio **P1** della specifica |
| `rustre-ti-shodan`, `rustre-ti-otx`, `rustre-ti-opencti` | 1 | 0-2 | client di servizi remoti; il loro limite è strutturale, non di scrittura (vedi §7) |

---

## 6. Livello 0 — COMPOSIZIONE (26)

Facciate, registry e crate di tipi. **Vanno giudicate sul fatto di essere complete**, e la maggior parte lo è:

- `rustre-arch-registry` (77 righe) cabla **tutte e 19** le architetture
- `rustre-loader-registry` (215 righe) ha adattatori completi per **13 formati**
- `rustre-il` (152 righe) è primitive condivise con 6 dipendenti — perfettamente sana
- `rustre-mobile` (43 righe) ri-esporta tutti e 7 i sotto-crate

Il difetto qui non è nel codice ma nel fatto che **due dei quattro registry non hanno alcun chiamante**. `rustre_arch_registry::register_all()` installa i 19 backend reali e per tutta la vita del progetto non è stata invocata da nessuno: il binario montava solo `PlaceholderArch`, il cui `disassemble` restituisce `Err("no backend linked")`. È stato collegato in questa sessione.

---

## 7. Tre limiti che nessuna crate può superare da sola

Non sono difetti di implementazione e nessun lavoro dentro la crate li risolve.

1. **Niente solver SMT.** `rustre-symb-engine` sa serializzare un problema in SMT-LIB2 (`to_smtlib2_script`, con test che verificano la presenza di `check-sat`) e non esiste nulla che lo risolva: `z3-sys` non compare in nessun `Cargo.toml`. L'esecuzione simbolica della §13 è oggi un **formattatore di vincoli**. Questo tiene `rustre-symb-*` e `rustre-deobf-opaque` sotto il loro potenziale.

2. **Niente Unicorn.** `rustre-emu` ha interpreti scritti a mano (`step_thumb16`, `step_x86_arith`). L'emulazione copre ciò che qualcuno ha avuto tempo di scrivere, non un'ISA. Questo limita `rustre-emu`, `rustre-emu-shellcode` e `rustre-sandbox-vm`.

3. **Niente rete per la threat intelligence.** `rustre-ti-*` interroga servizi remoti: senza chiave e senza traffico, l'unica risposta onesta è un errore tipizzato — che è ciò che ora fanno. Il loro livello non è migliorabile scrivendo altro codice locale.

Tutte e tre discendono dalla stessa decisione del 2026-07-12: eliminare ogni dipendenza nativa esterna. È una scelta difendibile — build riproducibili, nessun download — ma **non è mai stata propagata a `info.txt`**, che nelle §11, §12 e §13 promette ancora quelle capacità.

---

## 8. Le tre cose da fare, in ordine

1. **Collegare, non scrivere.** 81 crate di livello 2 e 16 di livello 3 hanno già il codice. Il lavoro con il rapporto valore/costo più alto del repository è dare loro una pipeline che le esercita — cioè un oracolo che possa dire che sono sbagliate. Il modello esiste già: le cinque metriche di `rustre-decompiler`.

2. **Il sottosistema plugin è il punto più debole rispetto alla specifica.** Quattro crate da 0.8-2.3k righe che devono realizzare il principio **P1** ("nel core ci sono solo trait"). È l'unico posto dove la sottigliezza dell'implementazione coincide con un principio non negoziabile.

3. **Decidere su Z3 e Unicorn.** Reintrodurli come *feature* opzionale, oppure riscrivere `info.txt` §11/§12/§13 per dire cosa esiste davvero. Lo stato attuale — specifica che promette, codice che simula — è la sorgente strutturale dei disallineamenti che questa sessione ha continuato a trovare.

---

## Appendice — riproducibilità

Ogni cifra viene da questi comandi, eseguiti dalla root:

```bash
# ampiezza API, moduli, byte reali
grep -rc 'pub fn ' crates/<c>/src --include='*.rs' | awk -F: '{s+=$2} END{print s}'
ls crates/<c>/src | wc -l
grep -rlE 'from_le_bytes|from_be_bytes|&\[u8\]' crates/<c>/src --include='*.rs' | wc -l

# integrazione: dipendenti e chiusura del decompilatore
grep -rl "\"<c>\"" crates/*/Cargo.toml | grep -v "crates/<c>/" | wc -l

# raggiungibilita' MCP
grep -rc '<c_con_underscore>::' crates/rustre-mcp-tools/src --include='*.rs'

# igiene
cargo clippy --release -p <c> --all-targets --message-format short 2>&1 | grep -c ': warning'
```

**Avvertenze di metodo, imparate sbagliando in questa stessa sessione:**

- Un crate che **non compila non emette lint**: un totale clippy misurato mentre qualcosa è rotto è più basso senza che nulla sia migliorato. Ogni misura qui è stata presa con `cargo check --workspace` a **0 errori**.
- `cargo check` **non esegue i lint clippy**. Sono due insiemi diversi.
- Un punteggio unico confonde struttura e integrazione, e penalizza le crate piccole e complete. Il primo tentativo metteva `rustre-loader-registry` ultimo; leggendolo si scopre che è finito.

---

## Appendice B — le 189 crate, elenco completo

Ordinate per livello, poi per struttura. `ST` struttura 0-6, `IG` integrazione 0-4, igiene A-D.

```

== 0-COMPOSIZIONE (26)
  ST=6 IG=4 igiene=A  rustre-analysis                pubfn=460  mods=15  16.6k
  ST=6 IG=4 igiene=A  rustre-flirt                   pubfn=349  mods=21  16.5k
  ST=6 IG=4 igiene=A  rustre-symbols                 pubfn=493  mods=20  22.2k
  ST=6 IG=2 igiene=A  rustre-diff                    pubfn=266  mods=19  16.9k
  ST=6 IG=2 igiene=A  rustre-emu                     pubfn=455  mods=17  17.6k
  ST=6 IG=2 igiene=A  rustre-forensics               pubfn=489  mods=16  17.3k
  ST=6 IG=2 igiene=C  rustre-fuzz                    pubfn=446  mods=15  15.5k
  ST=6 IG=2 igiene=A  rustre-sandbox                 pubfn=429  mods=12  16.0k
  ST=6 IG=2 igiene=B  rustre-symb                    pubfn=480  mods=18  17.6k
  ST=6 IG=2 igiene=A  rustre-threatintel             pubfn=328  mods=29  17.4k
  ST=6 IG=2 igiene=A  rustre-ttd                     pubfn=477  mods=14  15.7k
  ST=6 IG=1 igiene=A  rustre-mcp                     pubfn=613  mods=16  16.4k
  ST=5 IG=4 igiene=A  rustre-loader                  pubfn=412  mods=21  18.3k
  ST=5 IG=3 igiene=A  rustre-arch                    pubfn=301  mods=14  15.0k
  ST=5 IG=2 igiene=A  rustre-deobf                   pubfn=356  mods=16  17.4k
  ST=5 IG=2 igiene=A  rustre-dotnet                  pubfn=334  mods=14  15.6k
  ST=5 IG=2 igiene=B  rustre-hex                     pubfn=514  mods=13  17.5k
  ST=5 IG=2 igiene=A  rustre-net                     pubfn=349  mods=11  15.6k
  ST=5 IG=2 igiene=A  rustre-script                  pubfn=498  mods=14  15.7k
  ST=5 IG=2 igiene=A  rustre-syscalls                pubfn=345  mods=15  15.5k
  ST=5 IG=2 igiene=A  rustre-triage                  pubfn=203  mods=14  15.9k
  ST=5 IG=1 igiene=B  rustre-plugin-api              pubfn=597  mods=18  17.3k
  ST=2 IG=3 igiene=A  rustre-il                      pubfn=0    mods=1   0.1k
  ST=0 IG=2 igiene=A  rustre-mobile                  pubfn=1    mods=1   0.1k
  ST=0 IG=1 igiene=A  rustre-arch-registry           pubfn=2    mods=1   0.1k
  ST=0 IG=0 igiene=A  rustre-loader-registry         pubfn=2    mods=1   0.1k

== 1-ENTERPRISE (27)
  ST=6 IG=4 igiene=B  rustre-analysis-callconv       pubfn=296  mods=15  18.7k
  ST=6 IG=4 igiene=A  rustre-analysis-dataflow       pubfn=382  mods=20  23.7k
  ST=6 IG=4 igiene=A  rustre-analysis-fn             pubfn=270  mods=22  19.8k
  ST=6 IG=4 igiene=A  rustre-analysis-type           pubfn=354  mods=17  20.5k
  ST=6 IG=4 igiene=A  rustre-analysis-vsa            pubfn=346  mods=11  19.4k
  ST=6 IG=4 igiene=C  rustre-analysis-vtable         pubfn=340  mods=20  17.5k
  ST=6 IG=4 igiene=A  rustre-analysis-xref           pubfn=539  mods=21  19.9k
  ST=6 IG=4 igiene=A  rustre-core                    pubfn=811  mods=27  27.6k
  ST=6 IG=4 igiene=A  rustre-decompiler              pubfn=657  mods=38  79.9k
  ST=6 IG=4 igiene=A  rustre-decompiler-c            pubfn=277  mods=14  15.4k
  ST=6 IG=4 igiene=A  rustre-decompiler-cfs          pubfn=285  mods=11  17.5k
  ST=6 IG=4 igiene=A  rustre-decompiler-type         pubfn=476  mods=17  16.4k
  ST=6 IG=4 igiene=A  rustre-demangle                pubfn=313  mods=26  26.1k
  ST=6 IG=4 igiene=A  rustre-events                  pubfn=472  mods=11  15.6k
  ST=6 IG=4 igiene=A  rustre-flirt-apply             pubfn=361  mods=26  20.3k
  ST=6 IG=4 igiene=A  rustre-flirt-gen               pubfn=316  mods=24  17.7k
  ST=6 IG=4 igiene=A  rustre-il-lift                 pubfn=967  mods=39  88.6k
  ST=6 IG=4 igiene=A  rustre-il-passes               pubfn=287  mods=14  22.4k
  ST=6 IG=4 igiene=A  rustre-symbols-pdb             pubfn=256  mods=21  17.5k
  ST=6 IG=3 igiene=C  rustre-il-hlil                 pubfn=287  mods=9   27.0k
  ST=5 IG=4 igiene=B  rustre-analysis-cfg            pubfn=347  mods=25  25.4k
  ST=5 IG=4 igiene=A  rustre-arch-x86                pubfn=134  mods=20  36.9k
  ST=5 IG=4 igiene=A  rustre-decompiler-expr         pubfn=209  mods=12  16.0k
  ST=5 IG=4 igiene=A  rustre-il-llil                 pubfn=366  mods=12  21.6k
  ST=5 IG=4 igiene=A  rustre-loader-elf              pubfn=269  mods=22  21.3k
  ST=5 IG=4 igiene=A  rustre-loader-pe               pubfn=243  mods=21  18.1k
  ST=5 IG=3 igiene=B  rustre-il-mlil                 pubfn=379  mods=13  20.1k

== 2-AVANZATO-SPENTO (81)
  ST=6 IG=2 igiene=A  rustre-adb                     pubfn=397  mods=17  16.0k
  ST=6 IG=2 igiene=A  rustre-agent-llm               pubfn=441  mods=16  16.5k
  ST=6 IG=2 igiene=D  rustre-agent-prompts           pubfn=382  mods=15  15.9k
  ST=6 IG=2 igiene=D  rustre-analysis-string         pubfn=316  mods=20  17.3k
  ST=6 IG=2 igiene=D  rustre-deobf-iadl              pubfn=299  mods=15  15.1k
  ST=6 IG=2 igiene=D  rustre-deobf-mhcde             pubfn=335  mods=16  15.5k
  ST=6 IG=2 igiene=A  rustre-deobf-smc               pubfn=380  mods=19  16.5k
  ST=6 IG=2 igiene=D  rustre-deobf-string            pubfn=409  mods=20  17.4k
  ST=6 IG=2 igiene=B  rustre-deobf-vm                pubfn=360  mods=13  17.1k
  ST=6 IG=2 igiene=D  rustre-deobf-vmlift            pubfn=251  mods=18  17.0k
  ST=6 IG=2 igiene=D  rustre-dotnet-edit             pubfn=492  mods=15  16.8k
  ST=6 IG=2 igiene=A  rustre-fuzz-afl                pubfn=434  mods=15  16.0k
  ST=6 IG=2 igiene=A  rustre-fuzz-cov                pubfn=632  mods=19  16.4k
  ST=6 IG=2 igiene=A  rustre-fuzz-sanitizers         pubfn=490  mods=18  18.5k
  ST=6 IG=2 igiene=D  rustre-hex-pattern             pubfn=370  mods=12  15.9k
  ST=6 IG=2 igiene=A  rustre-loader-lua              pubfn=413  mods=16  16.3k
  ST=6 IG=2 igiene=C  rustre-loader-ole              pubfn=269  mods=18  17.2k
  ST=6 IG=2 igiene=A  rustre-mcp-server              pubfn=274  mods=10  17.4k
  ST=6 IG=2 igiene=A  rustre-mcp-tools               pubfn=4555 mods=17  127.2k
  ST=6 IG=2 igiene=A  rustre-mem                     pubfn=540  mods=35  23.5k
  ST=6 IG=2 igiene=C  rustre-mobile-dyld             pubfn=363  mods=19  17.6k
  ST=6 IG=2 igiene=B  rustre-pe-rebuild              pubfn=282  mods=16  16.1k
  ST=6 IG=2 igiene=D  rustre-symbols-stabs           pubfn=315  mods=19  17.0k
  ST=6 IG=2 igiene=A  rustre-trace-coresight         pubfn=267  mods=14  15.7k
  ST=6 IG=2 igiene=A  rustre-trace-pt                pubfn=339  mods=15  17.6k
  ST=6 IG=2 igiene=A  rustre-triage-entropy          pubfn=392  mods=22  17.1k
  ST=6 IG=2 igiene=D  rustre-ttd-query               pubfn=350  mods=14  16.0k
  ST=6 IG=2 igiene=C  rustre-ttd-recorder            pubfn=463  mods=13  16.7k
  ST=6 IG=2 igiene=C  rustre-ttd-replayer            pubfn=481  mods=18  16.0k
  ST=5 IG=2 igiene=A  rustre-agent                   pubfn=496  mods=15  16.0k
  ST=5 IG=2 igiene=A  rustre-agent-workflow          pubfn=367  mods=12  15.8k
  ST=5 IG=2 igiene=B  rustre-arch-6502               pubfn=131  mods=14  15.9k
  ST=5 IG=2 igiene=D  rustre-arch-68k                pubfn=297  mods=15  19.1k
  ST=5 IG=2 igiene=A  rustre-arch-avr                pubfn=220  mods=15  15.8k
  ST=5 IG=2 igiene=D  rustre-arch-dex                pubfn=201  mods=11  14.8k
  ST=5 IG=2 igiene=C  rustre-arch-jvm                pubfn=175  mods=10  16.2k
  ST=5 IG=2 igiene=C  rustre-arch-lua                pubfn=300  mods=15  17.1k
  ST=5 IG=2 igiene=A  rustre-arch-luajit             pubfn=218  mods=13  15.3k
  ST=5 IG=2 igiene=C  rustre-arch-msp430             pubfn=213  mods=18  16.4k
  ST=5 IG=2 igiene=D  rustre-arch-sparc              pubfn=245  mods=14  16.1k
  ST=5 IG=2 igiene=C  rustre-arch-wasm               pubfn=282  mods=12  15.4k
  ST=5 IG=2 igiene=D  rustre-arch-z80                pubfn=207  mods=15  16.6k
  ST=5 IG=2 igiene=A  rustre-crypto-id               pubfn=226  mods=14  16.3k
  ST=5 IG=2 igiene=B  rustre-debug                   pubfn=1549 mods=66  137.0k
  ST=5 IG=2 igiene=C  rustre-deobf-antianti          pubfn=221  mods=17  15.5k
  ST=5 IG=2 igiene=C  rustre-deobf-cff               pubfn=297  mods=16  16.2k
  ST=5 IG=2 igiene=D  rustre-diff-bindiff            pubfn=280  mods=12  15.4k
  ST=5 IG=2 igiene=B  rustre-diff-semantic           pubfn=303  mods=16  16.0k
  ST=5 IG=2 igiene=B  rustre-dotnet-metadata         pubfn=404  mods=10  16.3k
  ST=5 IG=2 igiene=C  rustre-forensics-fs            pubfn=357  mods=19  17.3k
  ST=5 IG=2 igiene=A  rustre-forensics-mem           pubfn=301  mods=15  17.0k
  ST=5 IG=2 igiene=D  rustre-fuzz-libfuzzer          pubfn=425  mods=15  15.7k
  ST=5 IG=2 igiene=D  rustre-fuzz-net                pubfn=473  mods=16  15.2k
  ST=5 IG=2 igiene=D  rustre-hex-template            pubfn=322  mods=12  16.4k
  ST=5 IG=2 igiene=C  rustre-hex-view                pubfn=387  mods=17  16.4k
  ST=5 IG=2 igiene=B  rustre-loader-android          pubfn=268  mods=15  15.7k
  ST=5 IG=2 igiene=A  rustre-loader-console          pubfn=242  mods=17  17.1k
  ST=5 IG=2 igiene=D  rustre-loader-firmware         pubfn=240  mods=11  14.9k
  ST=5 IG=2 igiene=C  rustre-loader-luajit           pubfn=232  mods=15  15.7k
  ST=5 IG=2 igiene=C  rustre-loader-macho            pubfn=178  mods=9   14.3k
  ST=5 IG=2 igiene=D  rustre-loader-wasm             pubfn=263  mods=14  15.2k
  ST=5 IG=2 igiene=B  rustre-mobile-smali            pubfn=218  mods=16  16.1k
  ST=5 IG=2 igiene=A  rustre-net-dissect             pubfn=267  mods=10  22.0k
  ST=5 IG=2 igiene=B  rustre-net-pcap                pubfn=257  mods=11  15.4k
  ST=5 IG=2 igiene=A  rustre-net-rules               pubfn=375  mods=14  17.2k
  ST=5 IG=2 igiene=A  rustre-pe-editor               pubfn=397  mods=14  16.5k
  ST=5 IG=2 igiene=A  rustre-sandbox-report          pubfn=270  mods=13  15.4k
  ST=5 IG=2 igiene=A  rustre-sandbox-vm              pubfn=427  mods=11  15.7k
  ST=5 IG=2 igiene=A  rustre-script-lua              pubfn=417  mods=16  17.7k
  ST=5 IG=2 igiene=A  rustre-script-python           pubfn=501  mods=14  16.7k
  ST=5 IG=2 igiene=A  rustre-script-rhai             pubfn=567  mods=15  16.0k
  ST=5 IG=2 igiene=A  rustre-symb-engine             pubfn=466  mods=13  16.3k
  ST=5 IG=2 igiene=A  rustre-syscalls-windows        pubfn=284  mods=10  18.3k
  ST=5 IG=2 igiene=A  rustre-sysinternals            pubfn=445  mods=15  16.0k
  ST=5 IG=2 igiene=C  rustre-ti-vt                   pubfn=361  mods=19  15.2k
  ST=5 IG=2 igiene=D  rustre-trace                   pubfn=539  mods=15  17.0k
  ST=5 IG=2 igiene=A  rustre-trace-coverage          pubfn=635  mods=19  16.8k
  ST=5 IG=2 igiene=A  rustre-trace-navigate          pubfn=609  mods=18  17.5k
  ST=5 IG=2 igiene=D  rustre-triage-die              pubfn=269  mods=17  17.9k
  ST=5 IG=2 igiene=A  rustre-ttd-replay              pubfn=440  mods=16  17.1k
  ST=5 IG=2 igiene=A  rustre-yara-engine             pubfn=276  mods=14  16.0k

== 3-COMPLETO-ISOLATO (16)
  ST=6 IG=1 igiene=A  rustre-yara-rules              pubfn=312  mods=16  16.1k
  ST=6 IG=0 igiene=A  rustre-bin                     pubfn=335  mods=17  16.1k
  ST=6 IG=0 igiene=A  rustre-crypto-oracle           pubfn=356  mods=17  16.2k
  ST=6 IG=0 igiene=A  rustre-crypto-whitebox         pubfn=333  mods=14  15.7k
  ST=6 IG=0 igiene=A  rustre-daemon                  pubfn=443  mods=15  15.4k
  ST=6 IG=0 igiene=A  rustre-emu-shellcode           pubfn=384  mods=18  15.9k
  ST=6 IG=0 igiene=A  rustre-plugin-host             pubfn=527  mods=17  15.1k
  ST=5 IG=1 igiene=A  rustre-graph                   pubfn=394  mods=8   16.9k
  ST=5 IG=1 igiene=A  rustre-mcp-federation          pubfn=582  mods=16  16.5k
  ST=5 IG=1 igiene=A  rustre-project                 pubfn=577  mods=15  16.6k
  ST=5 IG=1 igiene=A  rustre-triage-peid             pubfn=227  mods=14  16.0k
  ST=5 IG=0 igiene=A  rustre-cli                     pubfn=500  mods=18  16.5k
  ST=5 IG=0 igiene=A  rustre-sandbox-extract         pubfn=340  mods=15  16.8k
  ST=5 IG=0 igiene=A  rustre-sandbox-monitor         pubfn=419  mods=13  15.5k
  ST=5 IG=0 igiene=A  rustre-symbols-codeview        pubfn=278  mods=14  15.9k
  ST=5 IG=0 igiene=A  rustre-triage-yara             pubfn=387  mods=18  16.7k

== 4-INTERMEDIO-ESPOSTO (2)
  ST=4 IG=4 igiene=A  rustre-pe-tools                pubfn=227  mods=16  15.5k
  ST=4 IG=3 igiene=A  rustre-knowledge               pubfn=106  mods=8   4.1k

== 5-INTERMEDIO (23)
  ST=4 IG=2 igiene=C  rustre-arch-bpf                pubfn=152  mods=9   15.4k
  ST=4 IG=2 igiene=D  rustre-arch-cil                pubfn=231  mods=15  17.0k
  ST=4 IG=2 igiene=A  rustre-arch-ppc                pubfn=140  mods=11  16.0k
  ST=4 IG=2 igiene=D  rustre-deobf-opaque            pubfn=263  mods=15  15.5k
  ST=4 IG=2 igiene=C  rustre-loader-dotnet           pubfn=246  mods=16  17.2k
  ST=4 IG=2 igiene=C  rustre-loader-java             pubfn=218  mods=14  15.6k
  ST=4 IG=2 igiene=D  rustre-loader-pdf              pubfn=220  mods=15  15.5k
  ST=4 IG=2 igiene=A  rustre-mobile-ios              pubfn=255  mods=19  18.5k
  ST=4 IG=2 igiene=A  rustre-mobile-ipa              pubfn=223  mods=19  16.0k
  ST=4 IG=2 igiene=B  rustre-net-proxy               pubfn=395  mods=7   17.0k
  ST=4 IG=2 igiene=C  rustre-symbols-dwarf           pubfn=172  mods=15  17.2k
  ST=4 IG=2 igiene=A  rustre-ti-malpedia             pubfn=414  mods=19  15.8k
  ST=4 IG=2 igiene=C  rustre-ti-misp                 pubfn=427  mods=20  17.5k
  ST=4 IG=2 igiene=A  rustre-yara                    pubfn=226  mods=16  15.7k
  ST=4 IG=1 igiene=A  rustre-forensics-plugins       pubfn=256  mods=7   17.5k
  ST=4 IG=1 igiene=C  rustre-mobile-android          pubfn=247  mods=12  15.0k
  ST=4 IG=0 igiene=A  rustre-symb-taint              pubfn=585  mods=17  16.9k
  ST=4 IG=0 igiene=A  rustre-ti-correlate            pubfn=388  mods=18  15.9k
  ST=3 IG=2 igiene=A  rustre-arch-arm64              pubfn=154  mods=11  16.8k
  ST=3 IG=2 igiene=A  rustre-mobile-apktool          pubfn=224  mods=18  15.3k
  ST=3 IG=2 igiene=A  rustre-mobile-jadx             pubfn=234  mods=14  17.3k
  ST=3 IG=2 igiene=A  rustre-patch                   pubfn=73   mods=8   4.5k
  ST=3 IG=1 igiene=C  rustre-deobf-mba               pubfn=218  mods=13  16.3k

== 6-INDIETRO (14)
  ST=2 IG=4 igiene=B  rustre-analysis-typerecov      pubfn=57   mods=6   4.9k
  ST=2 IG=4 igiene=A  rustre-db                      pubfn=84   mods=7   3.4k
  ST=2 IG=2 igiene=B  rustre-arch-arm                pubfn=154  mods=7   15.2k
  ST=2 IG=2 igiene=D  rustre-arch-mips               pubfn=170  mods=7   16.0k
  ST=2 IG=2 igiene=C  rustre-arch-riscv              pubfn=91   mods=7   18.4k
  ST=2 IG=2 igiene=A  rustre-syscalls-linux          pubfn=231  mods=7   14.5k
  ST=1 IG=2 igiene=A  rustre-dotnet-decompile        pubfn=223  mods=6   16.8k
  ST=1 IG=2 igiene=A  rustre-plugin-lua              pubfn=24   mods=4   0.9k
  ST=1 IG=2 igiene=A  rustre-plugin-native           pubfn=19   mods=4   0.8k
  ST=1 IG=2 igiene=A  rustre-plugin-python           pubfn=37   mods=4   1.3k
  ST=1 IG=2 igiene=A  rustre-ti-opencti              pubfn=74   mods=5   3.0k
  ST=1 IG=2 igiene=A  rustre-ti-otx                  pubfn=36   mods=4   1.9k
  ST=1 IG=0 igiene=A  rustre-plugin-loader           pubfn=55   mods=4   2.3k
  ST=1 IG=0 igiene=A  rustre-ti-shodan               pubfn=13   mods=4   1.1k```
