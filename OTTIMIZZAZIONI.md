# OTTIMIZZAZIONI — audit del workspace RustRE

**Data:** 2026-08-22 · **Ambito:** 189 crate (`rustre-gui` incluso solo dove i numeri
aggregati lo comprendono, mai come oggetto di raccomandazione) · **Natura del
documento:** SOLO AUDIT. Nessuna ottimizzazione è stata applicata. Ogni voce dice
*cosa*, *dove* (crate + file + riga), *perché* e *quanto costa verificarla*.

---

## 0. Metodo, e il suo limite più importante

Le fonti lette per costruire la tassonomia:

| fonte | cosa fornisce |
|---|---|
| `rustc-dev-guide` → *Optimized build* | LTO, jemalloc/override-allocator, codegen-units, `target_cpu`, PGO, BOLT — con i guadagni dichiarati dal team rustc |
| Cargo Book → *Profiles* | semantica esatta di `opt-level`, `lto`, `codegen-units`, `panic`, `strip`, `debug`, override per pacchetto e `build-override` |

### ⚠ Il limite da leggere prima di tutto il resto

**Questo workspace non è misurabile oggi.** `criterion` è dichiarato
(`Cargo.toml:323`) ma esistono benchmark in **2 crate su 189**:

```
crates/rustre-debug/benches/   → full_coverage.rs, hot_paths.rs
crates/rustre-demangle/benches/→ demangle_bench.rs
```

Quindi ogni cifra di guadagno riportata qui sotto è **presa dalla documentazione
upstream o dedotta dalla struttura del codice, non misurata su RustRE**. Le ho
tenute separate: le colonne "guadagno" dicono sempre *dichiarato* o *atteso*, mai
*misurato*.

Questa non è una nota di cautela formale. È il primo intervento consigliato: il
repository ha già imparato a proprie spese (vedi `CLAUDE.md`, sezione
`measure.sh`) che un numero assoluto senza snapshot immutabile è
ininterpretabile, e che rendere una metrica più severa abbassa il numero senza
che il codice peggiori. **Ottimizzare senza banco di misura ripeterebbe
esattamente quell'errore su un asse nuovo.**

Dimensione dell'oggetto misurato, per calibrare tutto il resto:

```
4 102 file .rs      3 873 340 righe      86 796 funzioni pubbliche
```

---

## PARTE A — Livello build

### A.1 Ciò che è GIÀ fatto (e non va toccato)

`Cargo.toml:343-348`:

```toml
[profile.release]
opt-level     = 3        # massimo
lto           = "fat"    # LTO whole-program, la variante più aggressiva
codegen-units = 1        # nessuna frammentazione: massima qualità del codegen
panic         = "abort"  # niente tabelle di unwinding
strip         = true     # simboli rimossi
```

**Questo profilo è già alla configurazione di velocità massima descritta dal
Cargo Book** (`opt-level = 3` + `lto = "fat"` + `codegen-units = 1`). La leva di
build "facile" è esaurita. Chi cercasse qui il guadagno rapido non lo troverà: va
cercato nelle parti B e C.

Esiste anche `[profile.release-fast]` (`Cargo.toml:352-355`, `lto = "thin"`,
`codegen-units = 4`) per l'iterazione. Corretto e conforme al Cargo Book, che
descrive `thin` come "guadagni simili a fat con tempi molto minori".

### A.2 Ciò che MANCA — e la sua interazione non ovvia

| # | leva | stato | guadagno | dove agire |
|---|---|---|---|---|
| A-1 | `.cargo/config.toml` | **assente** | — | va creato in root |
| A-2 | `-C target-cpu` | **assente** | non quantificato upstream | `.cargo/config.toml` |
| A-3 | PGO | **assente** | **fino a 15%** (dichiarato rustc) | script di build |
| A-4 | BOLT | **assente** | non quantificato | post-link |
| A-5 | allocatore alternativo | **assente** | non quantificato | `rustre-bin`, `rustre-cli`, `rustre-mcp-server` |
| A-6 | `build-override` | **assente** | tempo di build | `Cargo.toml` |
| A-7 | `rust-toolchain.toml` | **assente** | riproducibilità | root |

**A-1 — non esiste `.cargo/config.toml`.** Verificato:
`find . -name config.toml -path '*.cargo*'` → nessun risultato. Non c'è quindi
alcun punto in cui il workspace fissi flag del compilatore, linker o
`target-cpu`. È il prerequisito di A-2.

**A-2 — `target-cpu`.** Il rustc-dev-guide indica
`RUSTFLAGS="-C target_cpu=x86-64-v3"`. RustRE è un decompilatore x86-64: i suoi
cicli caldi sono scansioni di byte, ricerche di pattern ed entropia, cioè
esattamente il carico che beneficia di AVX2 (incluso in `x86-64-v3`). **Costo:**
il binario smette di girare su CPU pre-2013. Se i binari vanno distribuiti,
questa leva va scartata o messa dietro un profilo dedicato; se restano interni,
è la leva di build più economica rimasta.

**A-3 — PGO.** Il guadagno dichiarato dal team rustc è *fino al 15%*, il più alto
di tutto il documento upstream. RustRE ha un vantaggio raro per applicarlo: **il
carico rappresentativo esiste già ed è versionato** —
`tests/decompiler_corpus/bin/*.exe`, 12 programmi reali C/C++/Rust/Go/C#, girati
dal driver `dump_decompile.exe`. Il profilo PGO si raccoglie eseguendo il driver
sul corpus, non serve inventare un workload sintetico. **Costo:** doppia
compilazione, e `llvm-profdata` deve essere disponibile.

**A-4 — BOLT.** Riordina il binario dopo il link secondo il comportamento a
runtime. Nel documento upstream è parte di `opt-dist`, richiede `llvm-bolt` e
`merge-fdata`, ed è dichiarato *opzionale*. Su Windows la disponibilità della
toolchain è il vero ostacolo. Ha senso solo dopo A-3.

**⚠ A-3/A-4 sono in conflitto con `strip = true` (riga 348).** PGO e BOLT — e
qualunque profiler — hanno bisogno dei simboli. Con `strip = true` il binario di
release non è profilabile. La forma corretta non è togliere `strip`, ma
introdurre un profilo dedicato:

```toml
[profile.release-pgo]
inherits = "release"
strip    = false
debug    = 1        # "limited": basta per i backtrace, non gonfia come debug=2
```

Questa interazione è il motivo per cui A-3 non è un flag da aggiungere, ma un
profilo da progettare.

**A-5 — allocatore.** Il rustc-dev-guide indica `override-allocator = "jemalloc"`
ma **solo per Linux e macOS**. Il workspace è primariamente Windows
(`win32`, Windows 10). L'equivalente portabile è `mimalloc` come
`#[global_allocator]` nei soli binari (`rustre-bin`, `rustre-cli`,
`rustre-mcp-server`) — mai nelle librerie, che non devono imporre un allocatore
ai consumatori. Rilevante perché la Parte C mostra un carico di allocazione molto
alto: dove si allocano milioni di `String`, l'allocatore *è* il collo di
bottiglia.

**A-6 — `build-override`.** Assente. I build script e le proc-macro sono
attualmente compilati con le impostazioni di default (non ottimizzati). Per un
workspace da 189 crate con `serde derive` diffuso, `[profile.release.build-override]
opt-level = 1, codegen-units = 256` accorcia il tempo di build senza toccare il
codice prodotto. **È l'unica voce della Parte A che non ha alcun rischio sul
risultato compilato**, perché per costruzione non entra nel binario.

**A-7 — nessun `rust-toolchain.toml`.** La versione di rustc non è fissata. Due
agenti su macchine diverse possono produrre binari con caratteristiche
prestazionali diverse, e nessuna misura sarebbe confrontabile. Prerequisito di
qualunque campagna di misura seria.

---

## PARTE B — Livello dipendenze

### B.1 `tokio` con `features = ["full"]` in 49 crate

`Cargo.toml:254`:

```toml
tokio = { version = "=1.40.0", features = ["full"] }
```

`full` attiva *ogni* componente: runtime multi-thread, I/O di rete, timer,
segnali, `process`, `fs`, sincronizzazione. **49 crate** hanno tokio fra le
dipendenze. La maggior parte di essi (i crate `rustre-analysis-*`, `rustre-arch-*`)
non fa I/O di rete né gestisce processi.

Effetto: tempo di compilazione e superficie di codice, **non** velocità a runtime
— con `lto = "fat"` il codice non chiamato viene rimosso dal binario finale.
Va quindi classificata come ottimizzazione del *ciclo di sviluppo*, non delle
prestazioni. Onestà richiesta: chi la vende come guadagno di runtime sbaglia.

Nota separata: la versione è **fissata esattamente** (`=1.40.0`). È una scelta
deliberata di riproducibilità, non un difetto; la segnalo perché blocca gli
aggiornamenti che portano ottimizzazioni upstream.

### B.2 `iced-x86` senza selezione di feature

`Cargo.toml:275` — `iced-x86 = "1.21"`, feature di default. `iced-x86` espone
feature granulari (decoder, encoder, i vari formatter Intel/AT&T/Nasm/Masm,
`instr_info`, `op_code_info`). Usato in:

```
rustre-arch-x86, rustre-il-lift, rustre-analysis-typerecov,
rustre-mcp-server, rustre-mcp-tools
```

più ~15 file di test in `rustre-arch-x86/tests/`, dove serve da **oracolo** di
confronto. Questo dettaglio conta: le feature richieste dai test non sono
necessariamente quelle richieste dalla libreria, e la selezione va fatta con
`dev-dependencies` separate, altrimenti si rompono gli oracoli
(`decode_table_vs_iced.rs`, `semantics_oracle.rs`, `simd_decoder_vs_iced.rs`, …).
Guadagno atteso: tempo di build e dimensione, non velocità.

### B.3 Dipendenze prestazionali già presenti e quasi inutilizzate

Questo è il ritrovamento più utile di tutta la Parte B. Sono **già** in
`Cargo.toml`:

```
Cargo.toml:302   rustc-hash = "2"      → usata in 16 punti su tutto il workspace
Cargo.toml:249   ahash      = "0.8"    → usata in 102
Cargo.toml:271   rayon      = "1"      → 32 file
Cargo.toml:300   smallvec   = "1"
Cargo.toml:301   indexmap   = "2"
Cargo.toml:270   dashmap    = "6"
Cargo.toml:264   parking_lot= "0.12"
```

Non c'è nulla da aggiungere e nulla da approvare: **gli strumenti sono già lì e
sono spenti.** È lo stesso schema che `MATURITA.md` documenta per i crate
("avanzato ma spento", 81 crate su 189) e che `CLAUDE.md` documenta per
`RUSTRE_LIBSIG_ARITY`. Ricorre a tre livelli diversi dello stesso progetto.

---

## PARTE C — Livello codice

Qui sta il grosso. Numeri misurati su tutti i 4 102 file.

### C.1 ⭐ Hashing: 3 281 mappe con chiave intera su SipHash

| pattern | occorrenze |
|---|---|
| `HashMap` | 15 909 |
| `HashSet` | 5 743 |
| di cui **con chiave `u64`/`u32`/`usize`** | **3 281** |
| `FxHashMap` | 137 |
| `AHashMap` | 272 |
| `BTreeMap` | 1 216 |

`std::collections::HashMap` usa SipHash-1-3, progettato per resistere ad attacchi
di collisione da input ostile. Per una chiave che è **un indirizzo virtuale** —
già uniformemente distribuita, e non scelta da un avversario — è puro costo:
`FxHashMap` (rustc-hash) su chiavi intere è tipicamente diverse volte più veloce,
ed è **già una dipendenza del workspace** (B.3).

L'esempio più significativo, perché è la struttura più interrogata di tutto un
tool di reverse engineering — l'indice degli xref,
`crates/rustre-analysis-xref/src/lib.rs:381-385`:

```rust
from_map:    HashMap<u64, Vec<Xref>>,
to_map:      HashMap<u64, Vec<Xref>>,
string_refs: HashMap<String, Vec<Address>>,
import_refs: HashMap<String, Vec<Xref>>,
type_refs:   HashMap<String, Vec<Xref>>,
```

e, nello stesso file, `:778` `HashMap<u64, usize>` per i conteggi, `:1133` e
`:1136` per la lista di adiacenza e i gradi entranti del grafo delle chiamate —
cioè le strutture percorse a ogni attraversamento.

Altri punti caldi con la stessa forma:

```
crates/rustre-decompiler/src/lib.rs            157 occorrenze di HashMap
crates/rustre-il-hlil/src/lib.rs                80
crates/rustre-analysis-vsa/src/lib.rs           69
crates/rustre-decompiler-expr/src/pattern_library.rs  69
crates/rustre-il-mlil/src/phi_placement.rs      62   ← inserimento dei nodi phi
crates/rustre-symb-engine/src/lib.rs            61
crates/rustre-analysis-type/src/interprocedural.rs    51
crates/rustre-analysis-cfg/src/lib.rs           51
crates/rustre-analysis-dataflow/src/def_use_analysis.rs  45
```

**Avvertenza sull'ordine di intervento.** `FxHash` non è resistente alle
collisioni ostili. Le mappe con chiave `String` proveniente da un binario in
analisi (`string_refs`, `import_refs` sopra: il contenuto arriva dal file
esaminato, che in questo dominio *è* potenzialmente ostile) vanno lasciate su
SipHash o passate ad `ahash`, non a `FxHash`. Questa distinzione — chiave interna
vs chiave controllata dall'input — decide voce per voce, e ignorarla
trasformerebbe un'ottimizzazione in una vulnerabilità DoS. È la stessa classe di
difetto che un agente ha appena chiuso in `rustre-pe-rebuild` (allocazione da
~4 GiB pilotata da un campo d'intestazione).

### C.2 Allocazioni: il volume

| pattern | occorrenze |
|---|---|
| `.to_string()` | **44 366** |
| `format!(` | **24 474** |
| `.clone()` | 19 556 |
| `Vec::new()` | 13 488 |
| `.to_owned()` | 4 931 |
| `.to_vec()` | 4 725 |
| `String::new()` | 3 756 |
| `with_capacity(` | **2 504** |

Il rapporto rilevante: **13 488 `Vec::new()` contro 2 504 `with_capacity`**. In
circa l'84% dei casi un vettore nasce vuoto e cresce per raddoppi successivi
(riallocazione + copia a ogni soglia), anche quando la dimensione finale è nota
in anticipo — per esempio quando si costruisce un vettore da un altro di
lunghezza conosciuta.

Non tutte queste occorrenze sono difetti: `Vec::new()` per un campo di struct
inizializzato vuoto è corretto, ed è il caso di
`crates/rustre-decompiler/src/lib.rs:268-269, 656-662`. **La riscrittura di massa
sarebbe un errore.** Il criterio utile è: `Vec::new()` seguito da un ciclo con
`push` la cui lunghezza è calcolabile prima.

### C.3 `format!` come chiave di mappa — 136 occorrenze

Formattare un valore in una `String` solo per usarla come chiave alloca a ogni
accesso. Esempi concreti:

```
crates/rustre-analysis-callconv/src/return_type_recovery.rs:377
    *self.votes.entry(format!("{ty:?}")).or_insert(0) += 1;

crates/rustre-analysis-fn/src/prologue_scanner.rs:752
    *hist.entry(format!("{:?}", m.arch)).or_insert(0) += 1;

crates/rustre-arch-68k/src/m68k_disassembler.rs:475
    slot.insert(format!("{prefix}_{addr:08X}"));

crates/rustre-arch-arm64/src/arm64_calling_conventions.rs:239-240
    self.save_rules.insert(format!("x{i}"), SaveRule::CallerSaved);
```

Il primo è il più istruttivo: `return_type_recovery.rs:377` **serializza un tipo
via `Debug` per contare voti**. Il conteggio funziona, ma alloca una stringa per
ogni voto e rende il risultato dipendente dalla rappresentazione `Debug` — che
non è un contratto stabile. Qui l'ottimizzazione e la correttezza indicano la
stessa modifica: usare il tipo stesso (o un enum/id) come chiave. È il caso in
cui una voce di audit prestazionale è in realtà una segnalazione di fragilità.

### C.4 `Regex::new` fuori da `LazyLock` — 56 costruzioni, 26 lazy

`Regex::new` compila un automa. Chiamarla dentro una funzione ricompila a ogni
invocazione. Sul totale di 56 costruzioni ci sono solo 26 usi di
`LazyLock`/`once_cell`/`lazy_static` in tutto il workspace.

Casi più netti, un costruttore che compila **sei** regex a ogni chiamata:

```
crates/rustre-sandbox-extract/src/lib.rs:1336-1342
    re_ipv4, re_url, re_domain, re_hash_md5, re_hash_sha1, re_hash_sha256

crates/rustre-sandbox-extract/src/c2_extractor.rs:448-449
    url_regex, ip_port_regex

crates/rustre-net-rules/src/lib.rs:527, :1791
    Regex::new(pattern.as_str())   ← dentro il percorso di valutazione delle regole
```

`net-rules:1791` è il più caro dei tre: sta nel cammino di match, quindi la
compilazione si ripete per pacchetto valutato.

I tre in `crates/rustre-analysis-fn/src/callgraph.rs:517-519` sono invece **dentro
i test** — vanno esclusi dalle raccomandazioni. Li elenco solo perché comparivano
nella misura grezza, e una misura non filtrata avrebbe gonfiato il numero.

### C.5 Scansioni lineari

```
.contains(&…)                6 633
.iter().position(…) / .find(…)  1 860
```

Non sono difetti di per sé: su una collezione di 5 elementi la scansione lineare
batte qualunque mappa. Diventano difetti quando la collezione cresce con la
dimensione del binario analizzato. **Questa classe non è decidibile per grep** —
richiede di guardare caso per caso da dove viene la collezione. La riporto come
*area da ispezionare*, con la dimensione del campione, non come lista di
interventi. Priorità di ispezione: i file già identificati in C.1 come caldi.

### C.6 Costruzione di stringhe — 2 585 `push_str`

Con `String::new()` (3 756 occorrenze) come punto di partenza, ogni `push_str`
oltre la capacità rialloca. `String::with_capacity` con una stima anche grossolana
elimina la catena di riallocazioni. Rilevante soprattutto nell'emissione del
decompilatore, che costruisce migliaia di file di C:
`crates/rustre-decompiler/src/lib.rs` ha da solo **594 `format!`**, il massimo del
workspace.

### C.7 Parallelismo: `rayon` presente in 32 file su 4 102

`rayon` è già dipendenza (`Cargo.toml:271`) e usata in `batch_mode.rs`,
`batch_decompiler.rs`, `memory_search.rs`, `demangler_cache.rs`, i tre file di
`crypto-whitebox`, `flirt/signature_matcher_new.rs` e poco altro.

Il candidato naturale non ancora coperto è la decompilazione per-funzione: il
corpus produce **11 342 file emessi** e ogni funzione è, in prima
approssimazione, indipendente. `batch_decompiler.rs` già parallelizza a livello
di binario; il livello di funzione all'interno di un binario è il grado di
parallelismo non sfruttato.

**Ostacolo reale, non teorico:** le passate del decompilatore condividono stato
mutabile. `CLAUDE.md` documenta che `name_stack_slots` (625 righe) è stato
lasciato non rifattorizzato proprio perché è una pipeline sequenziale su stato
condiviso, e che l'ordine delle passate decide il risultato
(`feedback_ordine_passate_decompiler`). Parallelizzare qui **cambierebbe l'output
emesso** senza che il compilatore se ne accorga — esattamente il difetto che le
metriche di fedeltà esistono per intercettare. Va fatto, se si fa, con
`measure.sh --label before/after` e `diff -rq` fra snapshot.

### C.8 `#[inline]`: perché NON è nella lista degli interventi

```
#[inline]          1 042
#[inline(always)]     15
funzioni pubbliche 86 796
```

A prima vista un rapporto bassissimo. Ma il profilo di release usa
`lto = "fat"` + `codegen-units = 1`: l'inlining fra crate è già a disposizione
dell'ottimizzatore su tutto il programma. Aggiungere `#[inline]` in massa
produrrebbe rumore nel diff e nessun guadagno dimostrabile.

**Lo riporto esplicitamente come non-raccomandazione**, perché è la voce che un
audit superficiale metterebbe in cima basandosi sul rapporto 1 042 / 86 796.

### C.9 I/O: 261 `fs::read` contro 4 file che usano mmap

```
fs::read(         261
read_to_string(   141
read_to_end(       36
```

`fs::read` carica l'intero file in memoria. Per un tool che apre eseguibili,
dump di memoria e trace, `memmap2` evita la copia e lascia paginare al sistema
operativo. Oggi la mappatura è usata in **4 file soltanto**:

```
crates/rustre-debug/src/lib.rs
crates/rustre-debug/src/snapshot_mmap.rs
crates/rustre-forensics/src/lib.rs
crates/rustre-gui/src/core/binary_buffer.rs
```

Nota di correttezza che precede quella di prestazioni: `memmap2` è `unsafe` per
costruzione (il file può cambiare sotto la mappatura) e il workspace ha
`unsafe_code = "warn"` a livello di lints (`Cargo.toml`), con 559 occorrenze di
`unsafe` già presenti. L'estensione della mappatura è quindi una decisione di
policy, non solo di prestazioni.

---

## PARTE D — Priorità

Ordinate per rapporto fra guadagno atteso e rischio di regressione, **non** per
guadagno assoluto.

| # | intervento | dove | guadagno | rischio | prerequisito |
|---|---|---|---|---|---|
| 1 | **Banco di misura** (criterion sui percorsi caldi) | crate di C.1 | nessuno diretto | nullo | — |
| 2 | `build-override` | `Cargo.toml` | tempo di build | **nullo** (non entra nel binario) | — |
| 3 | `rust-toolchain.toml` | root | riproducibilità | nullo | — |
| 4 | `FxHashMap` su chiavi intere | `analysis-xref:381`, `il-mlil/phi_placement`, `analysis-dataflow` | atteso alto | medio — vedi C.1 sulle chiavi da input | 1 |
| 5 | `LazyLock` sulle regex | `sandbox-extract:1336`, `net-rules:1791` | atteso alto, locale | basso | — |
| 6 | `format!` come chiave | `return_type_recovery:377` + 135 | medio (e corregge una fragilità) | basso | — |
| 7 | `with_capacity` mirato | C.2, solo cicli a lunghezza nota | medio | basso | 1 |
| 8 | PGO sul corpus | script | **fino a 15% dichiarato** | medio | 1, 3, profilo `release-pgo` |
| 9 | `target-cpu` | `.cargo/config.toml` | non quantificato | **alto** (compatibilità CPU) | decisione di distribuzione |
| 10 | allocatore (`mimalloc`) nei binari | `rustre-bin`, `-cli`, `-mcp-server` | atteso, legato a C.2 | basso | 1 |
| 11 | feature di `tokio`/`iced-x86` | `Cargo.toml:254, 275` | tempo di build | medio (rompe gli oracoli in `arch-x86/tests`) | — |
| 12 | `rayon` per funzione nel decompilatore | `rustre-decompiler` | atteso alto | **molto alto** — cambia l'output emesso | 1 + `measure.sh` |
| 13 | BOLT | post-link | non quantificato | alto | 8 |
| — | ~~`#[inline]` di massa~~ | — | **nessuno** | — | non raccomandato, vedi C.8 |

Le voci 1–3 non toccano una riga di codice compilato e vanno prima di tutto il
resto. La 12 è l'unica che può cambiare il *risultato* del decompilatore, e non
va avvicinata senza i due harness di fedeltà descritti in `CLAUDE.md`.

---

## PARTE E — Tre cose che questo audit NON dice

1. **Non dice quanto si guadagna.** Nessun numero qui è stato misurato su RustRE
   (§0). I "fino a 15%" del PGO sono il dato del team rustc sul *compilatore
   rustc*, un carico diverso.

2. **Non dice dove il tempo è speso davvero.** Un profiler non è stato eseguito —
   e con `strip = true` (riga 348) non lo si può eseguire utilmente sul binario
   di release attuale. La classifica della Parte D è per **densità di pattern e
   posizione nell'architettura**, che è un proxy, non una misura. È esattamente
   la distinzione fra ciò che `check.sh` vede e ciò che `behavior.py` vede, già
   documentata in `CLAUDE.md`.

3. **Non copre `rustre-gui`.** Escluso su indicazione esplicita. Compare solo nei
   totali aggregati, e in un punto è il primo classificato
   (`gui/src/core/signature_db.rs`, 174 `.clone()`): non è una raccomandazione.

### Il ritrovamento che vale più dei singoli numeri

Le tre leve di codice più promettenti — `rustc-hash`, `ahash`, `rayon` — sono
**già dipendenze dichiarate del workspace, usate rispettivamente in 16, 102 e 32
punti su 4 102 file**. Non manca la capacità: è presente e spenta.

È lo stesso schema che `MATURITA.md` misura sui crate (81 su 189 "avanzati ma
spenti") e che `CLAUDE.md` registra su `RUSTRE_LIBSIG_ARITY` (154 firme in
database, funzione che ritorna subito perché il flag è OFF). Tre livelli diversi,
un solo schema: **in questo repository il difetto tipico non è l'assenza, è il
cablaggio mancante.**
