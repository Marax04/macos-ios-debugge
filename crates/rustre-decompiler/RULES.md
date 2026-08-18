# Regole del decompilatore — elenco ricostruito

> ⚠️ **Come è nato questo file.** Il codice cita regole per numero (`REGOLA #28`,
> `REGOLA #2 del repo`, …) ma **l'elenco canonico non è mai esistito come file**:
> né in `crates/rustre-decompiler/`, né in `docs/`, né nella storia git
> (`git log --all --diff-filter=D -- '*.md'` non restituisce nulla).
>
> Le regole qui sotto sono **ricostruite dalle loro citazioni nel sorgente**, con
> la provenienza riga per riga. Dove una regola è citata ma il suo enunciato non
> è deducibile, è scritto che non lo è — non è inventata.
>
> Ricostruito il 2026-08-15. Fonti: `crates/*/src/*.rs`, `info.txt` §1.1,
> `dafare.txt`.

---

## Parte I — Principi architetturali (da `info.txt` §1.1)

Cinque decisioni non negoziabili. Quella che governa il decompilatore è **P2**.

| | Principio | Cosa impone qui |
|---|---|---|
| **P1** | Plugin everywhere — nel core solo trait | Loader/Architecture/Decompiler sono plugin; zero formati hardcoded |
| **P2** | **IR multi-livello: LLIL → MLIL (SSA) → HLIL** | **«Il decompiler ha come input HLIL.»** Ogni analisi seria lavora su IR, non su testo |
| **P3** | `MemoryProvider` unico | L'analisi è agnostica sulla fonte dei byte (file, processo, emulatore, trace) |
| **P4** | Knowledge graph persistente | Stato analitico su SQLite con event sourcing, mai solo in memoria |
| **P5** | MCP-first | Ogni capability del core è anche un endpoint MCP |

**Conseguenza diretta di P2, ed è la rotta del progetto:** la catena HLIL
(«path B») è l'architettura prevista; la catena testuale («path A») è ciò che
oggi spedisce. Il lavoro non è scegliere fra le due, è **portare A dentro B**
finché B non le è superiore su ogni metrica.

---

## Parte II — Regole operative ricostruite

### REGOLA #2 — un pass che no-oppa è un BUG, non un dettaglio
Un predicato che non attiva mai il pass che governa non è «conservativo», è
rotto. Corollario misurato: dare al crate dataflow un CFG a **un solo blocco**
rende `live_out` sempre vuoto e la risposta collassa nella differenza insiemistica
`kill \ gen` — il pass gira e non calcola nulla.
<sub>`rustre-decompiler/src/lib.rs` — doc su `compute_liveness`; secondo sito: catena DCE con `ends_in_terminator`.</sub>

### REGOLA #9 — il risultato deve essere deterministico
Nessun tie-break può dipendere dall'ordine di una `HashMap`. Si ordina su una
chiave esplicita (`BTreeMap`, versione numerica), mai sull'iterazione.
<sub>`rustre-decompiler/src/lib.rs` — risoluzione dei `TypeVar`.</sub>

### REGOLA #13 — il bilanciamento delle graffe è l'invariante strutturale
Ogni test di emissione verifica `count('{') == count('}')`. È l'invariante che
distingue «output brutto» da «output non parsabile».
<sub>`rustre-decompiler/src/lib.rs` — asserzione nei test di emissione.</sub>
<sub>⚠️ Verifica per occorrenza e **spoglia prima i letterali stringa**, altrimenti le graffe dentro le stringhe emesse falsano il conteggio.</sub>

### REGOLA #19 — un gate mai provato spento dà falsa protezione
Un flag va scritto come **funzione pura che prende il flag come argomento**
(testabile accesa e spenta) più un wrapper che legge l'ambiente. Anche i gate
`default-ON` devono avere l'opt-out (`…=0`): senza gruppo di controllo
verificabile, «le annotazioni non possono raggiungere l'output» è un argomento,
non una misura. Due motivi tecnici in più: `std::env::set_var` in edition 2024 è
`unsafe` e corre con gli altri test in parallelo.
<sub>`rustre-decompiler/src/lib.rs` — gate `RUSTRE_LLIL_VALIDATE`, `RUSTRE_MLIL_ANALYZE`.</sub>

### REGOLA #21 — *enunciato non recuperabile*
Citata solo in coppia con #29 («il collegamento va provato da un test»). Il testo
proprio della regola non compare in nessun sito. **Non ricostruita.**

### REGOLA #28 — path A deve restare BYTE-IDENTICO
Ogni passata nuova entra **su `func.hlil_pseudo_code` (path B)** e dietro gate
**opt-in, default OFF**. Così l'invariante «path A non è cambiato» vale *per
costruzione*, non per misura: a gate spento la funzione ritorna `false` e non un
byte emesso può cambiare.
Corollario già inciampato: **popolare una env var cambia l'output di path A**, quindi
anche l'ambiente rientra nel vincolo. Se un `.c` di path A cambia, è sospetto di
violazione, non rumore.
<sub>`rustre-arch-x86/src/lift.rs:3602, 3657, 10775` · `rustre-decompiler/src/lib.rs:18511, 20315, 20651, 20678, 26649, 28093, 28447`.</sub>

### REGOLA #29 — il collegamento va provato da un TEST, non solo da una metrica
Se una passata deve dimostrare che un crate è realmente usato (e non chiamato e
scartato), serve un test che lo raggiunga. Conseguenza pratica: le funzioni
stanno a scope di modulo e non annidate, perché una `fn` annidata non è
raggiungibile da `#[cfg(test)]`.
<sub>`rustre-decompiler/src/lib.rs` — mappa `HlilExpr` → `rustre_decompiler_expr::Expr`.</sub>

### Numeri citati ma senza enunciato recuperabile
**#1, #3–#8, #10–#12, #14–#18, #20, #22–#27.** Non compaiono in nessun sito del
sorgente. Se ne emerge una, va aggiunta qui con la sua provenienza.

---

## Parte III — Regole di misura (da `CLAUDE.md`, già operative)

1. **`measure.sh` è l'unico modo sanzionato di produrre un numero.** `out/` non è
   un oracolo: più agenti lo riscrivono in parallelo.
2. **Self-vs-self.** I confronti sono snapshot-vs-snapshot, mai contro `out/`.
3. **Nessun numero da un albero in movimento.** Fingerprint prima e dopo; se si è
   mosso, il run è TAINTED e le metriche non si pubblicano.
4. **La ricompilabilità da sola non è una prova.** È cieca all'essere
   confidentemente sbagliati: dei parametri fantasma compilano perfettamente.
5. **Una dichiarazione alza la ricompilabilità e non può muovere la
   linkabilità.** Solo una definizione può.
6. **Una passata di riparazione sintattica gira per ULTIMA**, dopo ogni
   produttore, altrimenti no-oppa in silenzio (che per la REGOLA #2 è un bug).

---

## Parte IV — L'obiettivo, in una riga

Da `dafare.txt`: non «mostrare pseudocodice», ma **ricostruire un workspace
completo** — IR neutra ad alta fedeltà, renderer *language-aware* per C/C++/Rust/
Go/C#, progetto sintetizzato ricompilabile, e un ciclo
`decompile → rebuild → diff → refine` con metadati di confidenza su ogni
ricostruzione.

Obiettivi correnti dichiarati dall'utente, in aggiunta:
**0 `goto` · 0 `JUMPOUT` · 100 % ricompilabile (e linkabile).**
