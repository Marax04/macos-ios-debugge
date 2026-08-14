# PROGRESS — FLIRT stack

Ogni voce: cosa, **misurato come**, risultato. Niente numeri non misurati.

## 2026-07-28 — Sessione 1 (baseline + Fase 0)

### Inventario (misurato)

| Crate | LOC (.rs) | `pub fn` | `unwrap/expect/panic/unreachable` | `unsafe` |
|---|---|---|---|---|
| rustre-flirt | 17 195 | 338 | 76 | 0 |
| rustre-flirt-gen | 18 376 | 310 | 164 | 0 |
| rustre-flirt-apply | 20 109 | 350 | 176 | 3 |
| **Totale** | **55 680** | **998** | **416** | **3** |

Duplicazione rilevata (conteggio da nomi di modulo/funzione):
- **8 implementazioni CRC16** distinte nei 3 crate.
- 3 parser `.pat`, 4 matcher, 5 applier, 2 propagatori di nomi, 3 resolver di
  conflitti — cioè famiglie di moduli paralleli `*_v2` / `*_new` mai unificate.

### Fatto

- **T0 — baseline verde.** `cargo test --release -p rustre-flirt
  -p rustre-flirt-gen -p rustre-flirt-apply`:
  - prima: **1 unit test fallito** + **2 integration test falliti** +
    **1 doctest rotto** (non compilava affatto);
  - dopo: **1644 passati, 0 falliti**.
  - Causa: 3 test asseriscono `crc16_flirt(&[]) == 0x0000` dichiarando
    CRC-16/X-25, ma l'implementazione (in *entrambi* i crate) è MCRF4XX senza
    final XOR → `0xFFFF`. Test allineati all'implementazione, con l'incertezza
    reale registrata come **T1** invece di essere nascosta.
  - Doctest `pat_parser_v2::parse_pat_line`: blocco ```` ``` ```` senza `text`,
    quindi rustdoc provava a compilare `<pattern_hex> …` come Rust. → ```text.

## 2026-07-28 — Iterazione 1 del loop (T2 parziale)

### Misurato

- `cargo clippy --release --all-targets` sui 3 crate: **106 warning**.
- `cargo test --release` sui 3 crate: **1648 passati, 0 falliti**
  (era 1644 → +4 test di regressione aggiunti in questa iterazione).

### Due bug reali trovati da clippy (non stile)

1. **Prototipi libc errati** — `rustre-flirt-apply/src/rename_propagator.rs:142`.
   Un unico loop assegnava a `strcpy, strcat, strdup, strchr, strrchr, strstr,
   strtok` la stessa forma `(char *s1, const char *s2)`, con un ramo `if` i cui
   due lati erano identici (quindi la distinzione prevista non faceva nulla).
   Conseguenze concrete: `strdup` riceveva un **parametro fantasma** (arity 2
   invece di 1) e il secondo argomento di `strchr`/`strrchr` era tipato
   puntatore invece di `int`. Questi prototipi vengono propagati ai chiamanti:
   una firma sbagliata con sicurezza è peggio di nessuna firma.
   → riscritti per funzione; 4 test di regressione aggiunti, incluso un
   controllo di arity contro le prototipi C standard di 18 funzioni e un
   controllo di unicità dei nomi.
2. **Test vacuo** — `rustre-flirt-gen/src/pat_writer.rs:710`:
   `assert!(!entries.is_empty() || true)` è costante-vero, quindi
   `test_pat_parser_round_trip` non poteva fallire in nessun caso. Reso reale;
   verificato che passa davvero (il parser funziona su quella riga).

Più `unused import PatternByte` rimosso da `flirt-gen/coff_archive.rs`.

**Lezione:** i 1644 test verdi della baseline includevano almeno un test
strutturalmente incapace di fallire. Il conteggio dei test non è una misura di
copertura.

## 2026-07-28 — Iterazione 2 del loop (T3: unificazione CRC)

### Misurato

- `cargo test --release` sui 3 crate: **1659 passati, 0 falliti**
  (1648 → 1659, +11 test aggiunti in questa iterazione).
- Implementazioni CRC-16 manuali: **11 → 1** modulo canonico
  (`rustre-flirt/src/crc.rs`). Verificato con grep che fuori da `crc.rs` non
  resta nessun loop CRC, tranne la tabella a 256 voci del writer (tenuta per
  velocità e pinnata da un test su tutti e 256 i byte).
- `cargo clippy --release --all-targets`: 106 → **135 warning**. ⚠️ **Non è un
  peggioramento del codice esistente**: il nuovo modulo e i nuovi test sono
  superficie in più sotto `--all-targets`. Il conteggio va ri-baselinato, non
  confrontato con quello vecchio.

### Il difetto vero: il CRC FLIRT era calcolato in due modi incompatibili

Le 11 implementazioni non erano copie: erano **tre algoritmi**, e il "CRC FLIRT"
era spaccato fra due metà dello stack, ciascuna internamente coerente e con i
suoi test verdi.

| Metà | Algoritmo | Chi |
|---|---|---|
| A | **X-25** (poly 0x8408, init 0xFFFF, **xorout 0xFFFF**) | `flirt_signature_writer::compute_crc16` (il **writer**), `flirt_engine::crc16_flirt` (il **validatore**), `pattern_extractor::crc16_flirt_std` (il **generatore**) |
| B | **MCRF4XX** (stesso poly/init, **senza** xorout) | `lib::crc16_flirt` (×2 crate), `match_validator::compute_flirt_crc` |

`x25(d) == mcrf4xx(d) ^ 0xFFFF` per **ogni** input — verificato esaustivamente
sui 256 byte singoli, quindi le due metà non coincidono **mai**, nemmeno per
caso. In pratica: ogni CRC scritto in una firma era il complemento bit-a-bit di
quello che il matcher ricalcolava.

Contorno: `flirt_engine.rs` documentava la funzione come "MCRF4XX ... final XOR
0xFFFF", che è autocontraddittorio (MCRF4XX **non** ha xorout), e il corpo
applicava lo XOR. Tre doc comment diversi dichiaravano "questo è il CRC di IDA
FLIRT" per algoritmi diversi.

Scelto MCRF4XX come canonico perché è ciò che usa il consumatore
(`match_validator`) e 2 delle 3 funzioni top-level. **La scelta è isolata in un
solo alias** (`crc::flirt_tail`): se T1 dimostrasse che flair usa X-25, si cambia
una riga e si allinea tutto lo stack.

### Test aggiunti (11)

Check value di catalogo per ogni variante; dimostrazione esaustiva su 256 byte
che X-25 e MCRF4XX differiscono sempre; mutua distinzione delle 4 varianti; casi
limite su input vuoto; equivalenza di **tutti** gli entry point del crate con
`flirt_tail`; equivalenza tabella-vs-bitwise su tutti e 256 i byte; e
`generator_tail_crc_agrees_with_the_canonical_definition` nel crate gen.

### Errore mio, da ricordare

Nell'iterazione 1 avevo rimosso `use ... PatternByte` perché `cargo build` lo
segnalava inutilizzato: era usato **solo** in `#[cfg(test)]`, quindi ho rotto la
compilazione dei test. `cargo build` e `cargo test` non compilano lo stesso
insieme di codice — un warning "unused" dal solo build non è una prova.

## 2026-07-28 — Iterazione 3 (T3 completato davvero + 4° crate)

### Correzione di un numero che avevo pubblicato sbagliato

Nell'iterazione 2 avevo scritto «11 implementazioni → 1, nessun loop CRC resta
fuori da `crc.rs`». **Era falso.** Il grep di verifica cercava solo
`0x8408|0xA001|0x8005`, cioè i polinomi *riflessi* e quello CMS; ha mancato
l'intera famiglia **CCITT-FALSE** (forward `0x1021`) e le varianti table-driven.
Le implementazioni reali erano **16**, non 11.

Lezione: una verifica per grep vale quanto il pattern che ci metti. Il test
`every_tail_crc_verifier_uses_the_same_algorithm` ora enumera i consumatori
**esplicitamente**, così «li ho trovati tutti?» smette di essere una domanda da
grep e diventa una domanda da compilatore.

### Il difetto era più grave del riportato: non due metà, ma tre algoritmi

Quattro punti dello stack verificavano/producevano **lo stesso campo** (il CRC di
coda di una firma) con **tre algoritmi diversi**:

| Chi | Ruolo | Prima | Dopo |
|---|---|---|---|
| `flirt_signature_writer::compute_crc16` | writer | X-25 | `flirt_tail` |
| `flirt_engine::CrcCheck::verify` | validatore | X-25 | `flirt_tail` |
| `pattern_extractor::crc16_flirt_std` | generatore | X-25 | `flirt_tail` |
| `match_validator::compute_flirt_crc` | validatore | MCRF4XX | `flirt_tail` |
| `pat_parser::verify_pat_crc` | validatore `.pat` | **CCITT-FALSE** | `flirt_tail` |
| `signature_matcher::PatternMatcher::crc16` | matcher | **CCITT-FALSE** | `flirt_tail` |
| `signature_extractor::crc16` + `crc16_fast` | **produttore** di firme | **CCITT-FALSE** | `flirt_tail` |

`signature_extractor::crc16_window` produce il CRC che finisce nelle firme
generate; era CCITT-FALSE mentre il matcher ricalcolava un CRC riflesso. La
tabella a 256 voci è stata ricostruita per il polinomio riflesso e il percorso
table-driven è pinnato al bitwise su **tutti** i 256 byte.

### Misurato (4 crate)

- `cargo test --release` sui 4 crate: **1945 passati, 0 falliti**
  (FLIRT 1662 + typerecov 283).
- FLIRT: 1659 → **1662** in questa iterazione.
- Polinomi CRC letterali fuori da `crc.rs`: **1** rimasto, la tabella riflessa
  del writer, documentata e pinnata da test.

### 4° crate: `rustre-analysis-typerecov` (baseline misurata)

| metrica | valore |
|---|---|
| LOC | 7 801 |
| test verdi (release) | **282** |
| clippy `--all-targets` | **205 warning** |
| `unsafe` | **0** |
| `unwrap/expect/panic` | 55 |
| `pub fn` | 54 |

Ha la cultura di test migliore dei quattro: oracle veri
(`live_surface_oracle.rs`, `partition_oracle.rs`, `logic_regressions.rs`), non
solo unit test. Ma ha **più warning clippy dei tre crate FLIRT insieme** (205 vs
135) su un settimo delle righe.

### ⚠️ Il presupposto del progetto è falso: Level 7 non esiste

`rustre-analysis-typerecov` **non dipende da nessun crate FLIRT**
(`Cargo.toml`: solo `rustre-analysis`, `rustre-analysis-type`, `thiserror`,
`serde`, `iced-x86`) e la stringa `flirt` **non compare mai** nel suo sorgente.

Quindi «FLIRT è un moltiplicatore diretto della type recovery» oggi non è vero:
il moltiplicatore è **zero**, perché il filo non è collegato. T17 promosso a task
di massimo valore — senza di esso tutto il lavoro sui crate FLIRT resta
invisibile al decompiler.

## 2026-07-28 — Iterazione 4 (T17: Level 7 collegato, e il suo limite reale)

### Misurato

- `cargo test --release` sui 4 crate: **1953 passati, 0 falliti** (1945 → 1953,
  +8 test del bridge).
- Prototipi pubblicati disponibili nel bridge: **88**.
- Prototipi nella ground truth del corpus (`prototypes.json`): **136**.
- **Intersezione: 0.**

### Fatto: il filo esiste

`rustre-analysis-typerecov` aveva già il connettore
(`register_function_signature` / `infer_function_signature`); mancava solo chi
lo usasse. Creato `rustre-flirt-apply/src/typerecov_bridge.rs`:

- `to_recovered_type`: `TypeDescriptor` → `RecoveredType`. Ciò che il lattice di
  destinazione non sa esprimere (`union`, `enum`, `void`) diventa `Unknown`, non
  un'approssimazione: a valle un tipo approssimato è indistinguibile da uno
  recuperato, quindi una mappatura lossy travestirebbe una supposizione da fatto.
- `publish_identifications`: pubblica solo per nomi con prototipo **pubblicato**;
  gli altri finiscono in `skipped_unknown_prototype`, che è un numero di prima
  classe e non un drop silenzioso.
- `rustre-flirt-apply` → `rustre-analysis-typerecov`. Nessun ciclo: typerecov non
  cita FLIRT, quindi la dipendenza va nel verso giusto (il consumatore di
  entrambi ospita il ponte).

8 test, fra cui l'end-to-end che parte da `Confidence::Low` su un indirizzo
sconosciuto e dimostra che dopo l'identificazione FLIRT la firma ha arietà e
convenzione corrette; e quello che verifica che un nome sconosciuto **non**
sporchi il registry.

### ⛔ Ma il valore non arriva ancora: intersezione zero

I 88 prototipi sono libc + Win32 di base (`memcpy`, `strlen`, `CreateFileA`…).
La ground truth del corpus è **interamente runtime mingw-w64/libgcc**:
`_Unwind_GetIP`, `_GetPEImageBase`, `_IsNonwritableInCurrentImage`,
`__acrt_iob_func`… Nessuno dei 136 nomi è fra gli 88.

**Quindi misurare il delta con `measure.sh` oggi darebbe zero per costruzione.**
Il meccanismo è corretto e testato, ma non ha nulla da dire sul corpus finché il
database di prototipi non copre ciò che il corpus contiene davvero. È T17b, ora
il vero blocco.

Non ho eseguito `measure.sh`: un numero che so essere zero per costruzione non è
una misura, è teatro.

Strumento di misura permanente aggiunto (sostituisce lo script usa-e-getta):
`cargo run --release -p rustre-flirt-apply --example prototype_coverage -- tests/decompiler_corpus/prototypes.json`

### Da valutare, non ancora un task

`SIGNATURE_REGISTRY` in typerecov è uno `static Mutex<HashMap>` globale di
processo. Funziona, ma è stato globale mutabile in una libreria: i test devono
serializzarsi a mano (il bridge usa un mutex apposta) ed esiste
`_clear_function_signatures_for_test` proprio per questo. Da rivedere se il
percorso diventa concorrente.

## 2026-07-28 — Iterazione 5 (T17b: il database di prototipi)

### Misurato

| metrica | prima | dopo |
|---|---|---|
| prototipi noti al bridge | 88 | **213** |
| copertura ground truth corpus | **0** / 136 | **125** / 147 |
| arità divergenti sui nomi condivisi | — | **0 su 125** |
| test verdi (4 crate, release) | 1953 | **1956** |

### Come, e perché non a mano

I 125 prototipi sono estratti **meccanicamente** dagli header mingw-w64
installati (`tools/gen_runtime_prototypes.py` → `runtime_prototypes.rs`, file
generato, con `header:riga` accanto a ogni voce).

Non li ho scritti a memoria di proposito: sono ~125 firme, e un prototipo
sbagliato compila perfettamente e poi corrompe i tipi di ogni chiamante. Con
125 firme scritte a mano la probabilità di sbagliarne qualcuna è ~1. L'estrattore
sbaglia in modo *sistematico* e quindi rilevabile da un test, non a caso.

Le variadiche sono escluse: una firma ad arietà fissa non può combaciare con
`...`, quindi pubblicarla asserirebbe il falso. Il test verifica anche che una
funzione marcata variadica nella ground truth **non** sia stata pubblicata.

### ⚠️ Da ora `fidelity_arity.py` non è più un oracolo indipendente

`prototypes.json` e `runtime_prototypes.rs` derivano **entrambi** dagli stessi
header mingw-w64. Il test di arietà resta utile — i due estrattori sono diversi e
registrano cose diverse (l'uno solo l'arietà, l'altro i tipi completi), quindi un
disaccordo segnala un bug di estrazione — ma **non** può dire se l'output emesso
dal decompiler è giusto.

Conseguenza operativa: se questi prototipi entrano nella pipeline, misurare
l'arietà emessa contro la stessa fonte è tautologico. Un salto da 122/135
verrebbe letto come miglioramento quando è solo l'eco del proprio input. Le
metriche portanti diventano **`behavior.py`** (esegue davvero il codice,
baseline 7/14) e **`cross_build.py`** (baseline 2 incoerenti su 1359).

### Restano fuori 22 nomi

Interni della CRT non presenti negli header pubblici: `_FindPESection`,
`_GetPEImageBase`, `_IsNonwritableInCurrentImage`, `_pei386_runtime_relocator`,
`__mingw_GetSectionForAddress`… Per questi servirebbe una fonte diversa (i
sorgenti mingw-w64, non gli header installati). Non li ho inventati.

### Nota operativa

A metà iterazione il workspace non caricava: un agente concorrente aveva
lasciato una chiave duplicata in `crates/rustre-debug-apple/Cargo.toml`. Si è
risolto da solo al retry — conferma che su questo repo conviene ritentare prima
di "riparare" il crate di qualcun altro.

## 2026-07-29 — Iterazione 6 (T17d: la presa giusta, catena completa)

### Avevo collegato la presa sbagliata

Verificato con grep su tutto il workspace: il registry di
`rustre-analysis-typerecov` (`register_function_signature` /
`infer_function_signature`) **non è letto da nessuno** in produzione — solo dai
suoi test, da un wrapper MCP e dal mio bridge. È una superficie isolata.

Il vero Level 7 è in un **altro crate**: `rustre-analysis-type`, in
`infer_function_signature_named(addr, name, cc, env, &lib_db)`. Il commento nel
sorgente dice letteralmente *"§6.6 level 7"* e *"published library prototypes win
over inference"*. Il decompiler chiama quella, non quella di typerecov: due
funzioni con lo stesso nome in due crate diversi.

### Misurato: la presa vera copriva 3 nomi su 136

| | prima | dopo |
|---|---|---|
| voci in `LibrarySignatureDb` | 70 | **206** |
| copertura ground truth corpus | **3** / 136 | **126** / 136 |
| test verdi (5 crate, release) | — | **2577** |

`LibrarySignatureDb::new()` popolava libc + POSIX + Win32 — cioè quasi nulla di
ciò di cui è fatto un binario mingw. Esteso con `mingw_runtime_sigs.rs`,
generato dallo stesso estrattore (secondo emettitore in formato `IpaType`).
`populate_mingw_runtime()` gira **per ultimo**, così una voce curata a mano non
viene sovrascritta da una estratta; un test lo verifica su `memcpy`.

Nota su un difetto dell'estrattore trovato e corretto: in `unwind.h` il tipo di
ritorno sta su una riga e il nome sulla successiva, e la mia regex non
attraversava il newline — perdeva `_Unwind_RaiseException`, `_Unwind_Resume`,
`_Unwind_ForcedUnwind` e tutta la famiglia SjLj. È esattamente il tipo di errore
*sistematico* che un estrattore fa e un test intercetta, contro l'errore *casuale*
di chi scrive a mano.

`_Unwind_FindEnclosingFunction` — il caso che il progetto sapeva essere
"perfettamente coerente e uniformemente sbagliato" (0 parametri in ogni build
contro un prototipo pubblicato di 1) — ora ha una risposta pubblicata, con test
dedicato.

### L'ultimo anello: il decompiler ora chiama il bridge

`binary_entry.rs::flirt_pairs_with_scanner` chiama `publish_identifications`
**dopo** `pipe_drop_ambiguous_flirt_names`, di proposito: un nome rivendicato a
più indirizzi si è contraddetto da solo, e pubblicarne il prototipo diffonderebbe
l'errore in ogni chiamante invece di contenerlo.

### ⛔ E qui la catena, finalmente viva, rivela l'anello successivo rotto

Con driver ricompilato (mtime verificata) su `sample1.exe`:

```
[flirt→typerecov] considerate 0, pubblicate 0, senza prototipo 0
```

**FLIRT trova zero match.** Le firme sono caricate — altrimenti la funzione
esce prima e non stamperebbe nulla — quindi il match si perde fra `scan_fast` e
`resolve_renames`. Il database dei prototipi e tutta la catena sono a posto, ma
senza match non c'è niente da propagare: **T17e è il nuovo collo di bottiglia.**

Aggiunta diagnostica dietro `RUSTRE_FLIRT_DEBUG=1` (firme caricate / match
grezzi / dopo resolve). La lettura è bloccata da un build rotto di
`rustre-decompiler` introdotto da un agente concorrente
(`collapse_redundant_casts` definito due volte) — non mia, e non l'ho
"riparata" nel crate di qualcun altro. Da ritentare.

## 2026-07-29 — Iterazione 7 (T17e: perché FLIRT trova zero match)

### Misurato

| | |
|---|---|
| firme in `msvcrt-x64.sigpack` | **8** |
| firme in `rust-stdlib-x64.sigpack` | **14** |
| **totale firme disponibili al decompiler** | **22** |
| dimensione di `assets/rust-stdlib.sig` (mai caricato) | **10 799 348 byte** |
| test verdi (5 crate, release) | **2580** |

### Causa immediata

L'intera capacità FLIRT della pipeline sono **22 firme scritte a mano**. Con 22
candidati, i 126 prototipi runtime dell'iterazione 6 non possono servire a nulla:
il passo di *identificazione* non ha niente da identificare. Non era un bug del
matcher.

### Causa radice: tre formati di firma scollegati

| formato | scritto da | letto da |
|---|---|---|
| `SIGPACK 1` (testo) | a mano, 22 voci | lo **scanner del decompiler** |
| `RFLIRTBIN\0` | bin `rust_stdlib_sigs` di `flirt-gen` | **solo `rustre-gui`** |
| `IDASGN` (IDA) | writer in `rustre-flirt/lib.rs` | `sig_file_loader` di `flirt-apply` |

Il database generato da 10.8 MB è letto dalla GUI e **da nessuno** sul percorso
di decompilazione. Il loader che *potrebbe* alimentare lo scanner
(`sig_file_loader`) pretende `IDASGN`, un formato che il generatore non emette
mai. Tre isole, zero firme scambiate.

È la stessa classe di difetto del CRC delle iterazioni 2–3 — produttore e
consumatore che non si parlano — ma al livello del formato del contenitore, e con
conseguenze molto maggiori: lì i CRC erano complementari, qui il file non si apre
proprio.

Consigliato in T27: unificare su **`IDASGN`**, perché è l'unico già scritto *e*
letto da due componenti, ed è anche l'unico che apre T15 (interoperabilità reale
con IDA/flair) e sbloccherebbe T1.

### 3 test che fissano il difetto

In `rustre-flirt-apply/tests/sig_database_is_reachable.rs`. Sono scritti come
**tripwire, non come aspirazione**: asseriscono lo stato attuale (il loader
rifiuta il database, i pack sono minuscoli) e falliranno il giorno in cui qualcuno
chiude il divario, costringendo a registrare la vittoria invece di lasciarla
passare inosservata.

### Nota operativa

Il percorso decompiler resta non compilabile per edit concorrenti di altri agenti:
prima `collapse_redundant_casts` duplicato in `rustre-decompiler`, poi `static`
dentro un `impl` in `rustre-analysis-callconv`. Ho spostato la diagnosi **dentro i
miei crate** invece di inseguire quelle modifiche — il difetto è stato trovato
lo stesso, e i test vivono dove posso mantenerli.

## 2026-07-29 — Iterazione 8 (T27: anche IDASGN è spaccato)

### Misurato

- test verdi (5 crate, release): **2583** (2580 → 2583, +3).
- Divergenza di layout confermata empiricamente, non dedotta.

### Il piano T27 aveva un presupposto, e l'ho verificato prima di costruirci sopra

T27 propone di unificare su `IDASGN` perché è l'unico formato già scritto **e**
letto. Quel piano regge solo se le due parti concordano sul layout. Dato lo
storico di questo repo, l'ho misurato.

**Non concordano.** A offset 34:

| | offset 34 | 35 | 37 | 40 |
|---|---|---|---|---|
| writer (`FlirtSigSerializer`) | `name_len:u8` | `alt_ctype_crc:u16` | — | — |
| loader (`SigHeader::parse`) | `n_funcs:u32` | | `pattern_size:u16` @38 | campo nome fisso 40..104 |
| **IDA pubblicato (flair)** | `library_name_len:u8` | `alt_ctype_crc:u16` | `n_functions:u32` | `pattern_size:u16` @41 |

Dando al loader un header in layout pubblicato, restituisce
`n_funcs > 1 000 000` — sono i byte del nome letti come `u32` — e un `lib_name`
preso dal padding. Il **writer è vicino al layout IDA reale; il loader no.**

### Corollario che spiega due blocchi vecchi

Se il loader non implementa il layout IDA, **non può leggere nemmeno un `.sig`
prodotto da flair**. Ecco perché T1 (la domanda sul CRC a input vuoto) e T15
(interoperabilità IDA) non erano verificabili dall'iterazione 1: non esisteva un
percorso funzionante verso un file IDA reale, e nessuno se n'era accorto perché
il loader è perfettamente coerente *con sé stesso*.

Quarta occorrenza della stessa classe di difetto in questa sessione: due parti
internamente coerenti che non si parlano (CRC → contenitori → header).

## 2026-07-29 — Iterazione 9 (T27: header IDASGN, entrambi i lati)

### ⚠️ Correzione a quanto scritto nell'iterazione 8

Avevo scritto: *«il writer è vicino al layout IDA reale; il loader è la parte
sbagliata»*. **Falso.** Erano sbagliati **entrambi**, in punti diversi:

- **loader**: leggeva `n_funcs:u32` a offset 34 — che è `library_name_len:u8` —
  e prendeva il nome da una finestra **fissa** 40..104;
- **writer**: metteva il nome **subito dopo** il byte di lunghezza, prima di
  `alt_ctype_crc` e `n_functions`.

Avevo confrontato il writer col layout pubblicato solo fino a offset 34 e
concluso troppo presto. Il byte 34 era giusto, tutto il resto no.

### Fatto

Entrambi i lati portati al layout pubblicato di flair:

```text
34  1  library_name_len
35  2  alt_ctype_crc
37  4  n_functions   (v6+)
41  2  pattern_size  (v8+)
43 ..  library name
```

Conseguenze strutturali, non solo di offset:

- **L'header è a lunghezza variabile.** `SigHeader::SIZE = 104` è ora deprecata
  e sostituita da `header_len()`. Il trie parte da lì invece che da una
  costante: prima veniva letto dall'offset sbagliato per **ogni** libreria il cui
  nome non fosse esattamente 61 byte, cioè in pratica sempre.
- `library_name_len` fuori dal buffer viene **rifiutato**, non troncato. Un
  `.sig` è input non fidato: un nome troncato produrrebbe un'identità di libreria
  plausibile e sbagliata.
- `n_functions` e `pattern_size` sono v6+/v8+: sui file più vecchi si riporta il
  campo legacy a 16 bit e `0`, invece di inventare un valore.

I 3 test tripwire dell'iterazione 8 sono stati **riscritti in positivo**: ora il
round-trip deve riuscire, più i casi limite (nome vuoto, nome lungo, lunghezza
oltre il buffer, header troncati, file pre-v8).

### ✅ Verificato (dopo attesa sul lock di build)

- `idasgn_writer_loader_roundtrip`: **5/5 verdi** — round-trip, lunghezza
  variabile del nome, rifiuto della lunghezza fuori buffer, header troncati,
  file pre-v8.
- `cargo test --release` sui 4 crate: **1964 passati, 0 falliti**
  (1956 -> 1964, +8 in questa iterazione).
- `rustre-analysis-type`: **621 passati, 0 falliti**.
- **Totale 5 crate: 2585** (era 2583).

Nota di metodo: al primo giro il lock della build directory era saturo — misurati
**64 processi cargo/rustc** di agenti concorrenti — e tre tentativi sono andati in
timeout. Ho registrato la verifica come *pendente* e l'ho detto esplicitamente,
invece di riportare il verde precedente come se valesse ancora. Rieseguito appena
il lock si e' liberato.

## 2026-07-29 — Iterazione 10 (T27: codec header canonico + E2E)

### Misurato

- 4 crate: **1977** passati, 0 falliti (1964 -> 1977, +13).
- `rustre-analysis-type`: **621**. **Totale 5 crate: 2598** (era 2585).
- `sig_header` (nuovo codec canonico): **8/8**.
- `sig_file_end_to_end` (generator -> loader): **5/5**.
- Siti header ancora sul layout vecchio: **3** (`flirt-gen/lib.rs` 8 riferimenti,
  `pat_sig_format.rs` 4, `coff_archive.rs` 1).

### Non erano due writer, erano quattro

Cercando il writer del trie ne sono emersi altri due, entrambi sul layout
sbagliato: `flirt_gen::pat_sig_format::SigFileHeader::serialize` (104 byte fissi)
e `flirt_gen::sig_writer::SigHeader::to_bytes` — piu' i rispettivi reader. In
totale **4 writer e 3 reader**, divisi su due layout incompatibili.

Questo significa anche che il fix del loader dell'iterazione 9, da solo, avrebbe
**rotto** la lettura dei file prodotti da `write_sig_file`, che e' il percorso di
scrittura reale. Non l'ho scoperto misurando l'output: l'ho scoperto cercando
chi altro scrivesse quel formato, prima di dichiarare chiuso il round-trip.

### Fatto: un codec, tutti delegano

`rustre-flirt/src/sig_header.rs` — encode + decode nel layout pubblicato, con la
tabella delle divergenze storiche nella doc. Stessa forma del fix CRC
dell'iterazione 3: il difetto ricorrente di questo repo e' N implementazioni
dello stesso formato, e la cura e' una sola definizione.

`SigWriter::to_bytes` ora delega. I test che leggevano `n_funcs` a offset 34 o il
nome da `40..104` sono stati riscritti per **decodificare col codec canonico**
invece di frugare a offset fissi: cosi' non possono piu' fissare un layout
sbagliato.

### E2E: il crossing che prima era impossibile

`sig_file_end_to_end.rs` scrive un `.sig` con `flirt-gen` e lo legge con
`flirt-apply`, verificando nome di libreria a tre lunghezze diverse (una
dimensione fissa nascondeva il bug: il nome tornava indietro corretto solo per
una lunghezza), conteggio funzioni, rifiuto di una lunghezza nome corrotta e
assenza di panic su ogni troncamento.

## 2026-07-29 — Iterazione 11 (T27: conversione dei siti rimasti)

### Misurato

- 4 crate, **dopo** la conversione dei 3 siti noti: **1978** passati, 0 falliti
  (1977 -> 1978).
- Writer/reader di header IDASGN convertiti in questa iterazione: **4**
  (`flirt-gen/lib.rs`, `pat_sig_format.rs` serialize+deserialize,
  `coff_archive.rs`, e il sesto parser trovato strada facendo in
  `flirt-apply/lib.rs::parse_sig_v9_header`).
- Test che fissavano il layout vecchio, riscritti per **decodificare** invece di
  leggere offset fissi: **11** (in `lib.rs`, `pat_sig_format.rs`,
  `coff_archive.rs`, `blitz.rs`, `blitz2.rs`).

### Non erano quattro writer, erano sei siti

L'iterazione 10 ne aveva contati 4 writer + 3 reader. Convertendoli e' emerso un
**sesto** parser (`parse_sig_v9_header` in `flirt-apply/lib.rs`), con la stessa
firma del difetto: `NumFunctions` a offset 34, nome da `40..104`, e una costante
`SIG_V9_HEADER_SIZE = 104`.

Il conteggio e' salito a ogni giro non perche' cambiasse il codice, ma perche'
ogni conversione rendeva visibile il successivo: finche' i test leggevano offset
fissi, passavano **confermando l'errore**.

### La lezione che vale oltre questo task

Gli 11 test riscritti erano tutti verdi prima, e tutti verdi dopo — ma prima
verificavano *che il layout sbagliato fosse quello sbagliato*. Un test che
frughi a offset costanti in un formato a lunghezza variabile non protegge il
formato: lo cementa. Ora decodificano col codec canonico, quindi non possono
piu' fissare un layout errato.

Casi limite ora coperti dai test riscritti: nome vuoto, nome oltre 255 byte (il
tetto vero, non i 63 imposti dalla vecchia finestra fissa), assenza di padding
dopo il nome, `pattern_size` a 41 e non a 38.

## 2026-07-29 — Iterazione 12 (T27: il difetto era anche nella LETTURA da disco)

### Misurato

- 4 crate: **1983** passati, 0 falliti (1978 -> 1983, +5).
- Siti convertiti in questa iterazione: **3** — un settimo reader
  (`inspect_sig_header`), il trie start di `load_sig_file_v9`, e l'helper di test
  `make_v9_sig_bytes` che fabbricava file nel layout sbagliato.

### La verifica pendente ha trovato un bug vero

Chiudendo l'iterazione 11 avevo dichiarato **non verificata** la conversione del
sesto parser, e non avevo pubblicato un numero. Rieseguendo:
`test_inspect_sig_header_v9` falliva con `lib_name` vuoto.

Causa: `inspect_sig_header` leggeva **esattamente 104 byte** dal file e trattava
una lettura piu' corta come "formato vecchio", restituendo un header **senza
nome**. Ma un header valido con nome corto sta sotto i 104 byte — quindi
praticamente *ogni* file valido veniva silenziosamente degradato a stub anonimo.

Questo non e' un bug di layout, ed e' il motivo per cui i test di round-trip
sull'header non lo avevano preso: e' un bug su **quanto file leggi prima di
decodificare**. Solo un test che passi dal filesystem poteva vederlo — ora
esiste (`variable_length_header_is_honoured.rs`, 5 test).

### E un helper di test che fabbricava file invalidi

`make_v9_sig_bytes` costruiva l'header a mano nel layout vecchio: ogni test che
lo usava stava validando il parser contro input gia' sbagliati. Ora costruisce
col codec canonico.

### Conteggio finale del difetto

Erano **sette** siti, non sei: quattro writer, tre reader, piu' due
`trie_start`/`pos` calcolati da una costante e un helper di test. Il conteggio e'
cresciuto a ogni iterazione (2 -> 4 -> 6 -> 7) perche' ogni conversione rendeva
visibile la successiva.

## 2026-07-29 — Iterazione 13 (il percorso .sig -> scanner, e cosa c'e' sotto)

### Fatto

Aggiunti a `FlirtScanner`: `from_sig_file`, `from_sig_bytes` e
`from_packs_and_sig_files`. Prima **non esisteva alcun percorso** da un `.sig`
caricato a uno scanner: il loader sapeva leggere il file, ma `FlirtScanner` si
costruiva solo da `SignaturePack`, che parla solo il formato testo. Ecco perche'
il decompiler identificava con 22 firme scritte a mano.

`from_packs_and_sig_files` combina pack curati e database generati, cosi'
adottare un `.sig` non fa perdere le voci verificate a mano.

### Misurato (con un esempio diagnostico eseguito, non dedotto)

Stesso pattern, stesso nome, due writer diversi di `flirt-gen`:

| writer | header | corpo del trie | firme lette |
|---|---|---|---|
| `rustre_flirt_gen::SigWriter` (in `lib.rs`, usato da `write_sig_file`) | ok | ok | **1** |
| `rustre_flirt_gen::sig_writer::SigWriter` | ok | **illeggibile** | **0** |

Quindi ci sono **due encoder di trie incompatibili**, e solo uno round-trippa.
L'header ora passa in entrambi (fix delle iterazioni 9-12); e' il corpo a
divergere. Un file prodotto dal secondo writer da' uno scanner **silenziosamente
vuoto** — a valle indistinguibile da "questo binario non contiene funzioni
note". Registrato come **T30**.

Trovato anche che `FlirtPattern` esiste come **due tipi distinti e non
collegati** in `rustre-flirt` e `rustre-flirt-apply` (**T29**).

### Verificato

- `scanner_from_sig_database`: **7/7** verdi (incluso il tripwire su T30).
- 4 crate: **1990** passati, 0 falliti (1983 -> 1990, +7).

Il lock della build directory era saturo (40 processi cargo/rustc concorrenti) e
tre tentativi sono andati in timeout; ho registrato la verifica come pendente e
l'ho completata appena il lock si e' liberato, invece di riportare il numero
precedente.

## 2026-07-29 — Iterazione 14 (T30: encoder di trie unificati)

### Misurato

- `scanner_from_sig_database`: **8/8** verdi.
- 4 crate: **1991** passati, 0 falliti (1990 -> 1991).
- Nessun codice morto residuo dopo la delega (verificato con `cargo build`).

### Fatto

`sig_writer::SigWriter::build` ora delega a `rustre_flirt_gen::SigWriter` —
l'unico dei due encoder che il loader sa decodificare. Il tripwire
dell'iterazione 13 e' stato riscritto in **positivo**.

Ma la parte che conta e' il secondo test: non basta che entrambi i writer
producano un trie *leggibile*, devono produrre le **stesse firme** sullo stesso
input. Due encoder entrambi leggibili ma discordanti sarebbero la stessa classe
di difetto del CRC — sarebbe solo diventata piu' difficile da vedere.

### La catena `.sig` ora regge da un capo all'altro

Con T27 (header), T30 (trie) e i costruttori dell'iterazione 13:
`flirt-gen` scrive -> `flirt-apply` legge -> `FlirtScanner` si costruisce.
Prima nessuno dei tre anelli reggeva.

## 2026-07-29 — Iterazione 15 (RFLIRTBIN leggibile, e il blocco vero)

### Misurato

- 4 crate: **2003** passati, 0 falliti (1991 -> 2003, +12).
- `rflirt_bin`: **9/9**; `real_database_loads_into_scanner`: **3/3**.
- Database reale convertito: **67 168 pattern**, 10 799 348 byte -> 5 364 929.

### Fatto

Nuovo modulo `rustre-flirt-gen/src/rflirt_bin.rs`: reader del formato
`RFLIRTBIN` **nello stesso crate del suo writer** (prima l'unico decoder viveva
in `rustre-gui`, che non sta sul percorso di decompilazione — ecco come un
database generato e committato da 10.8 MB diventa peso morto), piu' la
conversione a `IDASGN`.

Il reader tratta il file come input non fidato: ogni lunghezza e' verificata
prima dell'uso, un `count` dichiarato piu' grande del file viene respinto senza
allocare, e mask e prefix di lunghezza diversa sono un errore. Test dedicati:
un byte 0x00 letterale non deve essere confuso con un wildcard (perderlo
darebbe un pattern che matcha comunque *qualcosa*, semplicemente mai la cosa
giusta) e il troncamento a **ogni** offset non deve mai andare in panic.

### ⛔ E qui il blocco vero, che i test sintetici non potevano vedere

| pattern in ingresso | byte del `.sig` | firme decodificate |
|---|---|---|
| 1 | 211 | 1 |
| 2 | 251 | 1 |
| 20 | 1 806 | 1 |
| 100 | 8 227 | 1 |
| 1 000 | 90 028 | **1** |
| 67 168 (database reale) | 5.4 MB | **1** |

Il writer scrive tutto — il file cresce — ma **il decoder del trie restituisce
sempre un solo nodo**. Il loader puo' quindi esporre **una sola firma da
qualsiasi `.sig`**, e anche un database perfetto resta inutile. E' **T31**.

### Correzione a quanto ho dichiarato nell'iterazione 14

Avevo scritto: *«la catena .sig ora regge da un capo all'altro»*. Regge **per una
firma**, non per un database. I miei test di round-trip usavano 1-2 pattern e
asserivano `>= 1`, quindi non potevano distinguere "funziona" da "funziona
esattamente una volta". La differenza e' emersa solo appena ho usato il file
vero — che e' esattamente il motivo per cui valeva la pena scrivere quel test.

## 2026-07-29 — Iterazione 16 (T31 risolto: da 1 firma a 67 168)

### Misurato

| pattern scritti | firme decodificate (prima) | firme decodificate (dopo) |
|---|---|---|
| 1 | 1 | 1 |
| 1 000 | **1** | **1 000** |
| 20 000 | **1** | **20 000** |
| 67 168 (database reale) | **1** | **67 168** |

- 4 crate: **2003** passati, 0 falliti.

### La causa

Il payload della foglia scritto da `SigTrieNode::encode` non combaciava con
`sig_file_loader::read_leaf_payload` in due modi:

1. **Ordine campi ed endianness.** Writer:
   `crc_len:u8, crc16:u16 LE, module_offset:u16 LE`. Decoder:
   `crc_offset:u16 BE, crc_len:u8, crc:u16 BE`. Stesso *numero* di byte — motivo
   per cui `pos` restava allineato e il primo nodo sembrava funzionare — ma
   campi e endianness diversi, quindi i CRC uscivano come spazzatura.
2. **Il difetto fatale: nessun terminatore.** Il writer non emetteva il `0x00`
   che chiude la lista dei nomi extra. Il decoder leggeva quindi il byte di
   lunghezza-prefisso del **nodo successivo** come lunghezza di un nome extra e
   ne consumava un pezzo: da lì in poi lo stream era disallineato e ogni foglia
   successiva andava persa.

Da qui l'"esattamente 1": il primo nodo si decodificava (per coincidenza di
lunghezza), il secondo distruggeva la sincronizzazione.

### Perché nessun test lo vedeva

I round-trip delle iterazioni 10-15 usavano 1-2 pattern e asserivano `>= 1`.
Con un solo elemento il difetto è invisibile **per costruzione**: serve un
secondo nodo perché il disallineamento si manifesti. Il test sul database reale
lo ha trovato al primo colpo.

Il test ora asserisce l'**uguaglianza esatta** fra pattern convertiti e firme
esposte, non `>`: `>` nasconderebbe la perdita del 90%.

## 2026-07-29 — Iterazione 17 (il decompiler usa i database .sig: da 0 a 238 match)

### Misurato — end to end, sul corpus reale

`sample3_rust.exe` (driver ricompilato, mtime verificata):

| | prima | dopo |
|---|---|---|
| firme nello scanner | **22** | **67 190** |
| match grezzi | **0** | **238** |
| dopo `resolve_renames` | 0 | 238 |
| identificazioni viste dal ponte Level 7 | 0 | **20** |
| prototipi pubblicati | 0 | 0 (nessun nome Rust ha un prototipo pubblicato) |
| file `.c` emessi che cambiano | — | **59 su 213** |

Esempio concreto della differenza:

```diff
-    sub_140002620();
+    __rustc_d9b87f19e823c0ef_____rdl_alloc();
```

`sample1.exe` (C puro): 8 -> 67 176 firme, 0 -> 46 match grezzi, ma **0 dopo i
filtri** e output **identico**. Coerente: sono firme rust-stdlib su un binario C,
quindi quasi certamente falsi positivi, e il filtro di ambiguita' li ha
eliminati. E' il comportamento voluto — meglio nessun nome che un nome sbagliato.

### Fatto

`binary_entry.rs::build_scanner` ora carica anche i `.sig` binari, da
`RUSTRE_SIGDB_DIR`. **Opt-in, non automatico**: aggiungere firme cambia quali
funzioni vengono rinominate, ed e' un cambiamento visibile nella correttezza,
quindi va deciso di proposito. Un `.sig` malformato non riduce in silenzio lo
scanner ai soli pack: viene segnalato e si prosegue con i pack.

### Le due letture oneste di questo numero

1. **20 identificazioni, 0 prototipi pubblicati.** Non e' un difetto: sono
   funzioni Rust stdlib, e il database di prototipi copre libc + runtime
   mingw-w64. Il ponte fa la cosa giusta rifiutando di inventare.
2. **238 match grezzi -> 20 dopo i filtri.** Il grosso viene scartato da
   simboli/export gia' noti e dal filtro di ambiguita'. Quanti dei 218 fossero
   falsi positivi e quanti buoni scartati per eccesso di prudenza non e' ancora
   misurato — e' la prossima domanda, non una conclusione.

## 2026-07-29 — Iterazione 18 (T32: precisione dei match, contro un oracolo vero)

### L'oracolo

Il corpus contiene `sample3_rust.pdb`: i nomi reali prodotti dal toolchain vero.
E' **indipendente** da tutto questo stack — a differenza della metrica di arieta',
che ormai condivide la sorgente col nostro database di prototipi.

Strumento: `cargo run --release -p rustre-flirt-apply --example
match_precision_vs_pdb -- <exe> <pdb> <sig>`.

### Misurato (`sample3_rust.exe`, 67 168 firme)

| | |
|---|---|
| match grezzi | 240 |
| nomi distinti assegnati | **27** |
| presenti nel PDB | **15** |
| **assenti = falsi positivi certi** | **2** |
| non decidibili (identificatore troppo corto) | 10 |
| **precisione, limite inferiore** | **88.2%** sui 17 decidibili |

I due falsi positivi:
`proc_macro::bridge::client::state::BRIDGE_STATE::…::{{tls.shim}}` e
`__llvm_profile_is_continuous_mode_enabled`. Sono funzioni stdlib reali che
**non appartengono a questo binario** — il classico falso positivo FLIRT su
prologhi corti e comuni.

### ⚠️ Ho prodotto due numeri sbagliati prima di questo

- **96.3%** — confrontavo il nome demangled con hash (`__rustc[d9b8…]::
  rust_begin_unwind`) contro la forma v0-mangled del PDB
  (`_RNvCs4SDF…rust_begin_unwind`). Stessa funzione, hash e grafia diverse:
  segnalata come falso positivo quando non lo era.
- **11.1%** — correggendo il primo errore ho preso come identificatore la coda
  dopo l'ultimo `::`, che per un nome Rust legacy **e' l'hash di build**
  (`::h04ed6ec30fd55dfc`). Diverso a ogni compilazione, quindi mai presente:
  garantiva il fallimento.

Entrambi erano artefatti della **misura**, non difetti del matcher. Li registro
perche' la lezione e' generale: quando confronti simboli fra due build, normalizza
l'hash **prima** di concludere, e se un identificatore e' troppo corto per
essere prova (`fmt`, `new`) contalo come **non decidibile** invece di
assegnarlo — altrimenti la precisione la stai fabbricando.

### Limite dichiarato di questa misura

E' un **limite inferiore** sull'errore: un nome che esiste nel PDB ma e' stato
attaccato all'indirizzo sbagliato qui conta come "plausibile". Stringerlo
richiede di leggere i record `S_PUB32` con un parser PDB vero (`rustre-symbols-pdb`
esiste): passo separato.

- 4 crate: **2003** passati, 0 falliti.

## 2026-07-29 — Iterazione 19 (precisione a livello di INDIRIZZO, e un difetto grosso)

### Il difetto trovato misurando: 78% dei rename erano nomi VUOTI

Passando dal confronto "il nome esiste nel PDB?" a "cosa c'e' davvero a
quell'indirizzo?", e' emerso che **188 dei 240 rename assegnavano la stringa
vuota**. Rinominare `sub_140002620` in `""` e' peggio che lasciarlo: l'indirizzo
perde anche l'identita' che aveva.

Causa a monte, misurata: **25 965 dei 67 168 pattern (38.7%)** del database
rust-stdlib non hanno un `primary_name`. La conversione RFLIRTBIN -> .sig e'
fedele — il difetto e' nel generatore che ha prodotto quel database.

Ma c'era anche un difetto **nei miei crate**: `resolve_renames` propagava il
nome vuoto invece di scartarlo. Corretto: un match senza nome ora conta come
`skipped`. Effetto misurato: 240 -> **52** rename, **0 nomi vuoti**, precisione
invariata.

### Precisione (`sample3_rust.exe`, oracolo = PDB del corpus)

| | |
|---|---|
| indirizzi distinti rinominati | **52** |
| AGREE (nome giusto) | **17** |
| DISAGREE (falso positivo) | **6** |
| UNKNOWN (il PDB non sa) | 29 |
| **precisione sui decidibili** | **73.9%** (17/23) |

`UNKNOWN` non e' mai piegato da una parte: contarlo come successo fabbricherebbe
precisione, contarlo come errore inventerebbe difetti.

### Difetto in un crate non mio, registrato e non toccato

`rustre_symbols_pdb::resolve_name_for_address` restituisce `None` anche per un
indirizzo derivato **dal PDB stesso** (verificato su `0x1400010a0`). Ho usato
`scan_public_symbols`, che funziona, e ho lasciato stare il crate altrui.

### Quarta versione della misura, terza correzione

96.3% -> 11.1% -> 42.9% -> **73.9%**. Ogni salto era un artefatto della misura,
non un cambiamento del codice:
- 96.3%: confronto demangled-con-hash vs v0-mangled;
- 11.1%: preso l'hash di build come identificatore;
- 42.9%: lato PDB non demangolato, quindi `std::process::exit` risultava falso
  positivo di se stesso.
Solo dopo aver demangolato **entrambi** i lati e separato i nomi vuoti il numero
sta fermo.

- 4 crate: **2003** passati, 0 falliti.

## 2026-07-29 — Iterazione 20 (T33: recuperato il 38.7% del database — con un costo)

### Prima: una lacuna mia

Il fix dell'iterazione 19 (`resolve_renames` scarta i nomi vuoti) era **senza
test**. Aggiunto `empty_names_never_rename.rs`, 5 test: nome vuoto, nome di soli
spazi, i validi che devono sopravvivere accanto ai vuoti, l'invariante generale
"nessun rename porta mai un nome vuoto", e la non-interferenza col filtro di
confidenza.

### T33: perche' il 38.7% non aveva nome

Non erano pattern senza nome. **Tutti e 25 965 hanno esattamente un nome, a
offset 0, marcato `is_local`**: distruttori (`?dtor$10@…`), thunk di trait impl.
`primary_name()` richiedeva `is_public`, quindi li scartava.

Il nome di una funzione statica e' comunque il nome giusto per quel codice, quindi
la regola solo-pubblici buttava via oltre un terzo del database. `primary_name()`
ora preferisce un nome pubblico a offset 0 e **ripiega** su uno locale; i nomi a
offset diverso da 0 restano esclusi (etichettano qualcosa *dentro* la funzione).
5 test nuovi, piu' un test di `blitz.rs` che fissava la vecchia politica,
aggiornato dichiarando il cambiamento.

### ⚖️ Il risultato e' un compromesso, non una vittoria netta

| | prima (solo pubblici) | dopo (con fallback locale) |
|---|---|---|
| indirizzi rinominati | 52 | **240** |
| AGREE | 17 | **18** |
| DISAGREE | 6 | **10** |
| UNKNOWN | 29 | 212 |
| **precisione sui decidibili** | **73.9%** | **64.3%** |

+188 rename, ma **precisione in calo di 9.6 punti** e 4 falsi positivi in piu'.
La maggior parte dei nuovi nomi finisce in UNKNOWN perche' l'oracolo copre solo
i simboli **pubblici** del PDB — e questi sono per definizione locali. Quindi la
misura **non puo' dirimere** se i 188 siano un guadagno.

### I 10 falsi positivi sono una classe sola

Tutti collisioni fra **istanziazioni generiche**:
`<&T as Debug>::fmt` assegnato dove il PDB dice `<&str as …>`, `<&u8 as …>`,
`<&mut [u8] as …>`. Sono monomorfizzazioni della stessa funzione generica,
quasi identiche nei primi byte: FLIRT non puo' distinguerle dal prologo.
Non e' un difetto introdotto qui — esistevano anche prima, il fallback ne ha
solo esposte altre. La cura e' piu' contesto (CRC di coda piu' lungo, lunghezza
funzione), non una politica sui nomi: e' **T34**.

- 4 crate: **2013** passati, 0 falliti (2003 -> 2013).

### Decisione da prendere, non presa

Se la priorita' e' *non sbagliare mai un nome*, il fallback andrebbe reso
opt-in o marcato a confidenza piu' bassa. Se e' *dare piu' identita' possibile*,
va tenuto com'e'. I numeri sopra sono tutto cio' che serve per scegliere; la
scelta non e' mia.

## 2026-07-29 — Iterazione 21 (T34: perche' i falsi positivi, e la curva)

### La causa, misurata

Su `sample3_rust.exe` col database da 67 168 firme:

- **238 dei 240 rename vengono da firme SENZA alcun CRC di coda**;
- 199 hanno un prefisso **sotto i 16 byte**;
- il 74.1% del database *ha* un CRC — e quelle firme non agganciano quasi mai,
  correttamente, perche' le loro code non combaciano.

Cioe': i match sopravvissuti erano in stragrande maggioranza le firme **piu'
deboli**. E' esattamente il profilo del falso positivo, e spiega le collisioni
fra istanziazioni generiche: senza CRC e con un prefisso corto non resta nulla
per distinguere `<&T as Debug>::fmt` da `<&u8 as Debug>::fmt`.

### La curva precisione / richiamo

`FlirtScanner::set_min_bytes_without_crc(n)` — byte esatti minimi richiesti a una
firma **priva di CRC**. Le firme con CRC sono esenti: il CRC e' gia' la prova che
la soglia serve a sostituire.

| soglia | rename | AGREE | DISAGREE | precisione |
|---|---|---|---|---|
| **0** (default) | 240 | 18 | 10 | **64.3%** |
| **16** | 40 | 15 | **2** | **88.2%** |
| **24** | 21 | 6 | **0** | **100%** |
| 32 | 1 | 0 | 0 | n/d |

**16 e' il punto interessante**: conserva 15 dei 18 nomi corretti e taglia i
falsi positivi da 10 a 2. **24** e' perfetto ma butta via due terzi dei nomi
giusti.

Default **0**, cioe' comportamento invariato: alzare la soglia *rimuove* match,
e cambiare in silenzio quali funzioni vengono rinominate e' un cambiamento
visibile nella correttezza.

### Test (5)

Default permissivo; la soglia scarta le firme corte senza CRC; una firma lunga
senza CRC passa comunque (la soglia taglia le prove **deboli**, non tutte le
firme senza CRC); una firma **con** CRC e' esente dalla soglia di lunghezza;
e monotonia — alzare la soglia non puo' mai aggiungere match.

- 4 crate: **2018** passati, 0 falliti (2013 -> 2018).

## 2026-07-29 — Iterazione 22 (la griglia completa: due decisioni, una tabella)

### Misurato (`sample3_rust.exe`, oracolo = PDB)

Database: **all** = 67 168 firme (con fallback sui nomi locali),
**pubonly** = 41 203 firme (solo nomi pubblici a offset 0).

| database | soglia | rename | AGREE | DISAGREE | precisione |
|---|---|---|---|---|---|
| all | 0 | 240 | 18 | 10 | 64.3% |
| all | **16** | 40 | **15** | **2** | **88.2%** |
| all | 24 | 21 | 6 | 0 | 100% |
| pubonly | 0 | 91 | 19 | 9 | 67.9% |
| pubonly | **16** | 17 | **15** | **2** | **88.2%** |
| pubonly | 24 | 6 | 6 | 0 | 100% |

### La lettura

**La soglia domina il database.** A soglia 16 le due varianti danno lo **stesso**
risultato (15 giusti / 2 sbagliati); cambia solo quanti rename *in piu'* produce
`all` (40 contro 17), e quei rename extra finiscono tutti in UNKNOWN — sono nomi
locali che l'oracolo pubblico non puo' verificare.

Quindi le due decisioni non sono indipendenti: **scelta la soglia, la scelta del
database quasi non conta** per la precisione. Con soglia 0, invece, `pubonly` e'
leggermente migliore (67.9% vs 64.3%) e produce un quarto dei rename.

### ⚠️ Il secondo binario NON e' una validazione indipendente

`sample8_rust.exe` da numeri **identici** in tutte e sei le celle. Sospettando un
errore di misura ho verificato: i due binari hanno md5 diversi, e l'impronta
degli indirizzi+nomi agganciati differisce (`0x7334…` vs `0x33c5…`), quindi il
tool legge davvero due file diversi.

I conteggi coincidono perche' **entrambi linkano la stessa stdlib**: i match
cadono tutti nel codice di libreria, identico fra i due. Quindi l'evidenza resta
**n=1**: due binari dello stesso toolchain non sono due campioni. Servirebbe un
binario costruito con una versione diversa di rustc, o di un'altra libreria.

### Aggiunto

`to_sig_bytes_filtered(..., public_names_only)` piu' 2 test (il filtro tiene solo
i pattern con nome pubblico; e la monotonia — un filtro puo' solo togliere).

- 4 crate: **2020** passati, 0 falliti (2018 -> 2020).

## 2026-07-29 — Iterazione 23 (specificita': l'oracolo che non richiede simboli)

### L'idea

Il problema n=1 nasceva dal dipendere dal PDB, e il corpus ne ha due, entrambi
Rust con la stessa stdlib. Ma esiste un oracolo che **non richiede simboli**:
far girare un database **rust-stdlib** su un binario C, C++, Go o C#. Quel
binario non contiene la libreria standard di Rust, quindi **ogni match e' un
falso positivo per costruzione**. Nessun oracolo da fidarsi, nessuna
normalizzazione di nomi da sbagliare, nessun bucket UNKNOWN da discutere.

### Misurato — indirizzi distinti rinominati, 6 binari non-Rust

| binario | s=0 | s=8 | s=12 | s=16 | s=24 |
|---|---|---|---|---|---|
| sample1_c | 42 | 0 | 0 | 0 | 0 |
| sample2_cpp | 42 | 0 | 0 | 0 | 0 |
| sample4_go | **1 580** | 0 | 0 | 0 | 0 |
| sample5_cs | **2 928** | 2 | 1 | 0 | 0 |
| sample6_c | 44 | 0 | 0 | 0 | 0 |
| sample7_cpp | 435 | 0 | 0 | 0 | 0 |
| **TOTALE** | **5 071** | **2** | **1** | **0** | **0** |

### La conclusione, ora fondata

Senza soglia il database produce **5 071 rinomine sbagliate** su codice che non
contiene una riga di Rust. A soglia 8 crollano a 2, a **16 sono zero**.

Messo accanto alla curva PDB — dove la soglia 16 conserva **15 dei 18** nomi
verificati corretti — la scelta smette di essere un'opinione:

- **specificita'**: 5 071 -> 0 falsi positivi
- **sensibilita'**: conserva l'83% dei nomi verificati giusti

**Raccomandazione: soglia 16 come default.** Il default attuale (0) non e'
neutro, e' attivamente dannoso: rinomina male migliaia di funzioni su codice
estraneo. La decisione resta dell'utente, ma ora ha un costo misurato.

### Nota sul metodo

Questa e' **specificita'**, non precisione: un database che non aggancia nulla
avrebbe un punteggio perfetto qui. Va letta **accanto** ai numeri di precisione,
mai al posto loro — e i test lo dicono nel loro stesso commento.

- 4 crate: **2023** passati, 0 falliti (2020 -> 2023).

## 2026-07-29 — Iterazione 24 (T11: i parser contro input ostile)

### Perche' proprio ora

Negli ultimi giorni ho scritto o rifatto **tre** parser di formati che arrivano
da terzi: il codec dell'header `IDASGN`, il loader del trie `.sig`, e il
container `RFLIRTBIN`. Ognuno legge campi di lunghezza controllati da chi
fornisce il file — `library_name_len`, `prefix_len`, `mask_len`, `name_len`, il
`count` dei pattern — e ognuno di questi e' un'occasione di leggere oltre il
buffer. Un database di firme e' input non fidato quanto il binario da analizzare.

### Metodo: sweep deterministico, non casuale

Stesso seed, stesso corpus, stesso risultato a ogni esecuzione, cosi' un
fallimento e' riproducibile dal solo nome del test. Tre famiglie, perche'
rompono cose diverse:

- **troncamento** a ogni offset (gestione delle lunghezze mancanti);
- **corruzione di un byte** a ogni offset, con 5 valori — garantisce di colpire
  ogni campo di lunghezza singolarmente, invece di sperare che uno sweep casuale
  ci finisca sopra;
- **saturazione dei campi di lunghezza** a `0xFF` — la forma classica che
  trasforma una lunghezza dichiarata in un'allocazione enorme o in uno slice
  fuori dai limiti.

Piu' un caso mirato: un file da 14 byte che dichiara `u32::MAX` pattern deve
essere respinto **senza tentare l'allocazione**.

Il criterio e' volutamente basso e assoluto: **mai andare in panic**. Restituire
un errore e' successo; interpretare qualcosa di strano ma limitato e' successo.
Solo un crash e' fallimento.

### Un test che protegge lo sweep stesso

`the_corpus_the_sweep_mutates_is_actually_valid`: se il corpus base fosse
degenere (buffer vuoto, magic sbagliato), **ogni** test di mutazione passerebbe
senza esercitare un solo parser, e il verde non varrebbe nulla. Il guard verifica
che i file base siano davvero validi e vengano parsati (3 firme, 2 pattern).

Era la lezione dell'iterazione 1 — il test `assert!(x || true)` che non poteva
fallire — applicata prima di prendere la stessa fregatura.

### Risultato

7 test verdi, **nessun panic** in nessuna delle mutazioni. I bounds check scritti
nelle iterazioni 12-15 (rifiuto di `library_name_len` fuori buffer, `count`
verificato prima di allocare, `mask_len != prefix_len` come errore) reggono.

- 4 crate: **2030** passati, 0 falliti (2023 -> 2030).

## 2026-07-29 — Iterazione 25 (T11 chiuso: `.pat` e archivi `.lib`)

### Il guard ha trovato un difetto alla PRIMA esecuzione

Il test che protegge lo sweep — introdotto ieri — ha fallito subito: il mio
corpus `.pat` non era valido (`InvalidLine(1)`). Senza quel guard, tutti gli
altri test di mutazione sarebbero passati mutando spazzatura, esercitando solo
percorsi d'errore. Verde senza significato.

### Il difetto che ha fatto emergere: 4 parser `.pat`, 3 formati, nessuno comune

| parser | classico IDA | forma `apply` | forma `v2` |
|---|---|---|---|
| `apply::parse_pat_text` | ✗ | ✓ | ✗ |
| `flirt::PatParser` | ✓ | ✓ | ✓ |
| `flirt::parse_pat` (v2) | ✗ | ✗ | ✓ |
| `gen::PatParser::parse` | ✓ | ✗ | ✓ |

**Nessun formato e' accettato da tutti e quattro.** `apply` vuole `:` prima di
`crc_len` e valori **decimali**; `v2` vuole un campo `delta` in piu`; il classico
IDA non ha nessuno dei due. Quindi un `.pat` scritto per una parte dello stack
non e' leggibile da un'altra.

E' la quarta occorrenza della stessa classe — CRC, contenitore, header, e ora il
formato testo. Registrato come **T4b**.

Conseguenza sul metodo: ogni parser riceve il corpus che **lui** accetta.
Mutare un formato che un parser rifiuta a priori eserciterebbe solo il suo
percorso d'errore.

### Coperto in questa iterazione

- `.pat`: troncamento a ogni byte, corruzione di ogni carattere con 8 valori,
  lunghezze dichiarate assurde (`FFFFFFFF`), riga da 100 000 caratteri, nome da
  100 000 caratteri, UTF-8 multibyte tagliato a meta', input vuoto/NUL.
- **archivi `.lib`**: troncamento e corruzione a ogni byte, piu' la forma
  **archive bomb** — un file da 40 byte il cui header di membro dichiara
  9 999 999 999 byte di contenuto — e archivi casuali con e senza magic valido.

**9 test, nessun panic.**

- 4 crate: **2039** passati, 0 falliti (2030 -> 2039).

## 2026-07-29 — Iterazione 26 (T12: misurato prima di difendere)

### Ho misurato invece di aggiungere limiti

T12 proponeva tetti espliciti: numero massimo di membri, dimensione dichiarata
massima, profondita' di ricorsione. Prima di scriverli ho misurato se servissero.

| input | tempo | esito |
|---|---|---|
| 1 000 membri (60 KB) | 0 ms | 1 000 visitati |
| 10 000 membri (600 KB) | 3 ms | 10 000 visitati |
| **50 000 membri (3 MB)** | **19 ms** | 50 000 visitati |
| 1 membro che dichiara **9 999 999 999** byte | 0 ms | respinto |
| 1 000 membri che dichiarano 999 999 byte | 0 ms | fermato al primo |
| archivio troncato a 200 byte | 0 ms | 2 membri, nessun errore |

Il parser ar limita ogni membro alla lunghezza **reale** del file, quindi una
dimensione dichiarata non puo' provocare una lettura grande, e il costo cresce
linearmente con i byte su disco.

### Conclusione: nessun cap, e la ragione conta

Un tetto sul numero di membri aggiungerebbe una manopola che **rifiuta archivi
legittimi** — un `.lib` reale puo' contenere decine di migliaia di membri — per
difendersi da qualcosa che e' gia' limitato. Aggiungere una difesa non misurata
non e' prudenza: e' complessita' con una probabilita' di falso rifiuto.

Il deliverable e' quindi un **guard contro la regressione**, non un limite: 5
test che falliscono se l'harvester diventa super-lineare. Le soglie sono
volutamente larghe (secondi contro millisecondi misurati) perche' devono
rilevare un cambio di **complessita'**, non una macchina occupata — un test
temporale stretto sarebbe instabile e verrebbe disattivato al primo falso
allarme.

### Limite dichiarato

Tutti i membri di questo stress sono blob non-oggetto, quindi il percorso
costoso — parsing di un COFF/ELF vero e visita dei suoi simboli — **non e'
esercitato**. Questo limita la gestione del **contenitore**, non del contenuto.

- 4 crate: **2044** passati, 0 falliti (2039 -> 2044).

## 2026-07-29 — Iterazione 27 (T13: determinismo, e due test vacui evitati)

### Il difetto: iterazione su `HashMap` nell'harvester

`coff_archive::harvest_object_bytes` iterava direttamente
`by_section: HashMap<SectionIndex, Vec<Symbol>>`. Rust randomizza l'hasher, quindi
per un oggetto con piu' sezioni `.text*` l'ordine dei pattern emessi cambierebbe
a ogni esecuzione, rendendo il `.sig` diverso **da se stesso**. Ordinato per
indice di sezione: costo trascurabile (poche sezioni), rischio azzerato.

Perche' conta: senza determinismo un database non e' checksummabile ne'
cacheable, una regressione non e' bisectabile, e "l'output e' cambiato" smette di
essere una prova — proprio la trappola per cui esiste `measure.sh`.

### Due volte il test stava per essere vacuo

1. I miei archivi sintetici contengono blob **non-oggetto**: non raggiungono mai
   il codice che cammina sulle sezioni. Un test di determinismo costruito su
   quelli sarebbe passato senza esercitare nulla.
2. Passato ai `.lib` del corpus, il guard di vacuita' ha fallito subito:
   `objects_parsed = 0`. Sono **import library** C# NativeAOT — un membro, zero
   oggetti, zero pattern.

Solo `libz.a` del toolchain mingw (15 oggetti, 132 pattern) esercita davvero il
percorso. Il test lo usa, con skip esplicito se assente.

E' la terza volta in tre iterazioni che il guard di vacuita' — introdotto
nell'iterazione 24 — trova un test che sarebbe passato senza provare niente.

### Coperto

7 test: writer byte-identico su 8 esecuzioni; conversione RFLIRTBIN->sig
identica; filtro solo-pubblici deterministico; il **parser** preserva l'ordine
(un writer deterministico e' inutile se il reader rimescola); stesso input ->
stesso digest; harvest di un archivio reale stabile su 5 esecuzioni; e `.sig`
costruito da archivio reale byte-identico.

- 4 crate: **2051** passati, 0 falliti (2044 -> 2051).

## 2026-07-29 — Iterazione 28 (T9: i 3 `unsafe` non esistevano)

### Correzione a un numero della mia baseline

L'inventario di apertura riportava **3 `unsafe` in `rustre-flirt-apply`**. Era
sbagliato: il grep contava la **parola** `unsafe`, e tutti e tre gli hit erano
dentro commenti che dicevano che il codice la evita di proposito
(`casts.rs`: *"no unsafe, no as-cast"*).

Misurato con un pattern corretto: **zero costrutti `unsafe` in tutti e quattro i
crate**, e cosi' e' sempre stato. E' la stessa lezione del grep incompleto
dell'iterazione 3, stavolta applicata al mio stesso inventario.

### Da accidentale a strutturale

Zero `unsafe` "per ora" e' piu' debole di "il compilatore rifiuta di
compilarlo". Aggiunto `#![forbid(unsafe_code)]` a tutti e quattro i crate.
**`forbid`, non `deny`**: `deny` e' aggirabile con `#[allow(unsafe_code)]` su un
item interno, quindi un blocco potrebbe rientrare senza toccare la radice del
crate. Compilano tutti con l'attributo attivo.

La motivazione e' concreta: questi crate analizzano `.sig`, `.pat` e `.lib` di
terze parti, e in un parser di input non fidato ogni errore di memoria e' un bug
di sicurezza.

### 4 test, con due difese incrociate

- l'attributo e' presente in ognuno dei quattro crate (`forbid` protegge il
  codice; il test protegge **l'attributo**, che si puo' cancellare);
- e' `forbid` e non `deny`;
- scansione diretta dei sorgenti: nessun costrutto `unsafe`, **ridondante di
  proposito** — se qualcuno togliesse l'attributo *e* aggiungesse `unsafe`, il
  primo test coglie la rimozione e il terzo il codice, quindi nessuna delle due
  meta' basta a passare in silenzio;
- **e un guard sullo scanner stesso**: verifica che riconosca `unsafe` quando
  c'e' davvero (4 forme) e che **non** scatti su commenti che nominano la parola
  — cioe' il falso positivo che aveva prodotto il "3" iniziale.

- 4 crate: **2055** passati, 0 falliti (2051 -> 2055).

## 2026-07-29 — Iterazione 29 (D5 rimisurato: 416 -> 50)

### Il terzo numero di baseline sbagliato, stesso metodo

D5 dichiarava **416 `unwrap/expect/panic!`**. Rimisurato distinguendo il codice
di **test** da quello di **produzione**:

| crate | unwrap | expect | panic! | (in test) |
|---|---|---|---|---|
| rustre-flirt | 2 | 1 | 0 | 73 |
| rustre-flirt-gen | 8 | 0 | 1 | 156 |
| rustre-flirt-apply | 32 | 0 | 0 | 139 |
| rustre-analysis-typerecov | 0 | 6 | 0 | 48 |
| **produzione** | **42** | **7** | **1** | **416** |

**50 in produzione, non 416.** I 416 erano quasi tutti in `#[cfg(test)]`, dove
un panic e' il comportamento **corretto** — un test che non fallisce non serve.
Piu' 24 occorrenze dentro commenti.

Terza volta in questa sessione che un numero di baseline si rivela un artefatto
di grep (dopo "11 CRC" e "3 unsafe"). Il metodo comune: contare una parola invece
di un costrutto, e non distinguere test da produzione.

### Triage dei 50 reali

- **~20** sono `data[a..b].try_into().unwrap()` su slice a dimensione fissa:
  l'`unwrap` e' **infallibile** (la lunghezza e' costante); il rischio vero e'
  l'indicizzazione, che nei parser di input non fidato e' **gia' protetta** da un
  controllo di lunghezza a monte. Verificato su `ida_sig_compat`
  (`HEADER_FIXED_SIZE = 88`, piu' un `data.len() >= 92` separato per il campo
  v6+): i guard sono corretti.
- il resto sono `.lock().unwrap()` su mutex, `.max().unwrap()` su collezioni non
  vuote per costruzione, ed `expect` su overflow `u32` documentati e limitati.

Nessuno dei 50 e' un panic raggiungibile da un `.sig`/`.pat`/`.lib` malformato —
coerente con lo sweep ostile delle iterazioni 24-25, che non ne ha innescato
nessuno.

### Trovato: un settimo layout IDASGN, e senza consumatori

`ida_sig_compat::IdaSigHeader` implementa **un terzo layout ancora** — nome
libreria come campo NUL-padded a 22..86, `alt_crc16` a 86 — diverso sia dal
codec canonico sia da quello che `sig_file_loader` usava prima della correzione.
E **nessuno fuori dal modulo lo chiama**: e' codice morto che implementa una
terza lettura incompatibile dello stesso formato.

Non l'ho cancellato (e' una decisione separata) ma l'ho **coperto**: e' API
pubblica, quindi un consumatore del crate puo' raggiungerlo. 2 test in piu',
con guard di validita' del corpus.

- 4 crate: **2057** passati, 0 falliti (2055 -> 2057).

## 2026-07-29 — Iterazione 30 (D4 rimisurato: sbagliato in entrambe le direzioni)

### Il quarto numero di baseline

D4 dichiarava "~12 moduli duplicati/paralleli". Misurato:

| | dichiarato | reale |
|---|---|---|
| moduli con nome parallelo (`*_v2`, `*_new`) | ~12 | **3** |
| di cui **codice morto** (0 consumatori nel workspace) | — | **2** (935 righe) |
| **tipi pubblici duplicati** | non contati | **52** |

Sbagliato in **entrambe** le direzioni: molti meno moduli paralleli del
dichiarato, ma 52 tipi pubblici con lo stesso nome — che il conteggio per moduli
non catturava affatto. `SigHeader` esiste **5 volte**, `ApplyResult`, `TrieNode`
e `PatternTrie` 4 ciascuno.

Il conteggio dei **tipi** e' quello che conta. Un modulo duplicato e' ordine; un
**tipo** duplicato e' la forma che ha prodotto **ogni** difetto reale di questa
sessione — due `FlirtPattern`, due layout `SigHeader`, tre encoder di trie. Ogni
coppia fa round-trip felicemente nella propria meta' dello stack e fallisce solo
dove le meta' si incontrano.

### Un tentativo fatto e ritirato

Ho marcato i due moduli morti `#[deprecated]`. Ha prodotto **8 warning** per i
loro stessi test, e il lint scatta alla radice del crate dove sta `pub mod`:
nessun `#[allow]` dentro il modulo li silenzia.

L'ho **ritirato** invece di puntellarlo. Un warning permanente su cui nessuno
puo' agire insegna a ignorare i warning, e quel costo supera il segnale. La nota
"Dead code" nel doc comment porta la stessa informazione senza rumore, e un test
verifica che resti.

Ritirando ho anche trovato un difetto mio: l'edit dell'iterazione 20 aveva
lasciato **il vecchio doc comment** sopra il nuovo su `primary_name` — diceva
ancora "(offset 0, public)", cioe' il comportamento che avevo appena cambiato —
piu' un `#[must_use]` duplicato. Rimossi entrambi. Build: **0 warning**.

### Consegnato

4 test che fissano l'inventario: i tipi duplicati non superano 52, i quattro
peggiori non peggiorano *individualmente* (uno shift resterebbe invisibile a un
totale che regge), i moduli paralleli non superano 3, e i due moduli morti
restano documentati come tali. Piu' un guard di vacuita': se lo scan trovasse
meno di 100 tipi, la soglia sarebbe finta.

- 4 crate: **2061** passati, 0 falliti (2057 -> 2061). Build senza warning.

## 2026-07-29 — Iterazione 31 (D9: benchmark e gate di non-regressione)

### Misurato

Database: `assets/rust-stdlib.sig` convertito in `IDASGN`, **67 168 firme**, 7.6 MB.

| metrica | valore |
|---|---|
| costruzione indice | **103 ms** (~650 firme/ms) |
| scan `sample3_rust.exe` (79.5 KB) | **148.8 MB/s** |
| scan `sample4_go.exe` (534.5 KB) | **235.4 MB/s** |
| scan `sample7_cpp.exe` (173.5 KB) | **213.5 MB/s** |
| scan `sample1_c.exe` (6.5 KB) | 173.0 MB/s |

Proprieta' verificate, non solo numeri assoluti:
- **10x input -> 5.1x tempo** (sublineare: l'indice Aho-Corasick ammortizza);
- **5 scansioni / 1 scansione = 5.4x** — l'indice **non** viene ricostruito a
  ogni chiamata, che sarebbe il difetto piu' facile da introdurre.

### Perche' niente criterion

Aggiungere un framework di benchmark come dipendenza per rispondere a "e'
abbastanza veloce, ed e' peggiorato?" e' piu' macchinario di quanto serva. E le
statistiche di criterion implicherebbero una precisione che una macchina
condivisa, con build concorrenti, non puo' dare.

### Il gate: soglie larghe di proposito

4 test con bound a circa un ordine di grandezza dal misurato (3 s contro 103 ms;
10 MB/s contro 235). Devono cogliere un cambio di **complessita'** — uno scan
accidentalmente O(n*m), un indice ricostruito per chiamata — non una macchina
occupata. Un gate tarato vicino al valore misurato fallirebbe per motivi
estranei al codice, e un test che grida al lupo viene disattivato: a quel punto
non protegge piu' nulla.

Ogni test ha il suo guard di vacuita' (firme > 1000, byte scansionati > 100 000):
un database che non carica costruirebbe istantaneamente e passerebbe.

### Pulito un residuo mio

`SIG_V9_HEADER_SIZE = 104` era inutilizzata dall'iterazione 12 **ed e'
concettualmente sbagliata** — l'header e' a lunghezza variabile. Rimossa insieme
al commento di layout obsoleto che la accompagnava: una costante che nomina un
invariante falso invita qualcuno a riusarla. Un test la usava ancora
(`cargo build` non lo compila: terza volta che questa lezione si presenta).

- 4 crate: **2065** passati, 0 falliti (2061 -> 2065).

## 2026-07-29 — Iterazione 32 (clippy: separare i bug dallo stile)

### Rimisurato: 428 warning sui 4 crate

Ma il totale non e' la domanda utile. Triage per categoria: **una sola** famiglia
ha il profilo del difetto reale — `match_same_arms` (11 occorrenze), la stessa
famiglia di lint che nell'iterazione 1 scopri' i prototipi libc sbagliati. Il
resto e' stile (37 backtick nei doc, 26 confronti f32/f64, 23 letterali senza
separatori) o cast troncanti gia' triati in T10.

### Il difetto trovato: 8 match arm irraggiungibili

`typevar_for_register` in `mem_access_scanner.rs` chiama `full_register()` e
**poi** elenca `Register::EAX => 1` ... `EDI => 8` come "alias a 32 bit".

Verificato eseguendo, non deducendo: `full_register()` mappa `EAX -> RAX`,
`AL -> RAX`, `AX -> RAX`, `R8D -> R8`, `SPL -> RSP`. Quegli 8 arm sono
**irraggiungibili**.

Peggio che ridondanti: elencando solo gli alias a 32 bit lasciavano credere che
**solo** quelli fossero gestiti, invitando qualcuno a "completare" la lista con
i registri byte o `R8D..R15D` — lavoro morto in partenza, e con l'occasione di
introdurre uno slot sbagliato mentre sembra una correzione.

### Sostituiti dalla proprieta' che cercavano di esprimere

4 test:
- tutte le larghezze dello stesso registro condividono uno slot, su **quattro**
  famiglie di larghezza (64/32/16/8) e 10 registri — se non fosse cosi', scrivere
  `al` e leggere `rax` apparirebbe come due valori scorrelati e il solver non li
  unificherebbe mai;
- registri **distinti** non collidono — lo specchio della proprieta' sopra, ed e'
  quello che intercetta un refuso: due registri sullo stesso id fonderebbero tipi
  non correlati in silenzio;
- i non-GPR (XMM, segmenti, ST0, RIP) non hanno slot: restituire `Some`
  permetterebbe di unificare stato floating-point con stato intero;
- la mappatura e' deterministica — la ragione stessa per cui esiste.

- 4 crate: **2069** passati, 0 falliti (2065 -> 2069).
- clippy `typerecov`: 205 -> **197**.

### Nota su un difetto in un crate non mio

`rustre-analysis-type/src/lib.rs:437`: `TypeConstraint::Deref { .. } => {}` ha
corpo identico a `ReturnOf`/`ArgumentOf`. In un constraint solver un vincolo
`Deref` che non fa nulla significa **informazione di dereferenziazione
scartata**. Non l'ho toccato: e' il quinto crate. Registrato come T39.

## 2026-07-29 — Iterazione 33 (T25: proprieta' dell'unificatore)

### Prima, il `match_same_arms` nel mio codice

`typerecov_bridge::to_recovered_type` aveva `Bool` e `U8` con corpo identico.
E' intenzionale — il lattice non ha booleani e un `bool` C **e'** un byte
unsigned — ma scritto come due arm separati sembra una distinzione incompiuta.
Uniti in un solo arm con la ragione scritta: e' esattamente cosi' che si era
nascosto il bug del prototipo `strdup` nell'iterazione 1.

### T25: proprieta', non esempi

I test esistenti verificano set di vincoli specifici contro tipi attesi
specifici. Cio' coglie una risposta sbagliata sui casi a cui qualcuno ha pensato;
**non** coglie una relazione di equivalenza che equivalenza non e'.

Il union-find significa quel che deve significare solo se l'unificazione e'
**riflessiva, simmetrica, transitiva** e se la soluzione e' **indipendente
dall'ordine**. Rompendone una il solver continua a produrre risposte — solo
diverse a seconda dell'ordine in cui i vincoli sono arrivati. E' il tipo di bug
peggiore: riproducibile solo a volte.

10 test:
- riflessivita' (un self-edge non corrompe la classe ne' cicla);
- simmetria (`a=b` e `b=a` danno lo stesso risultato — se differissero, "uguale"
  non vorrebbe dire uguale);
- transitivita', **e a profondita' 200** (catena lunga: verifica anche che la
  path compression eviti lo stack overflow);
- **indipendenza dall'ordine**: tutte le rotazioni cicliche del set piu' l'ordine
  inverso. Conta concretamente — i vincoli nascono camminando le istruzioni,
  quindi qualsiasi riordino (una `HashMap`, un chunk parallelo) non deve
  cambiare i tipi, altrimenti il merge cross-funzione dipende dallo scheduling;
- idempotenza sui vincoli duplicati (il generatore puo' emettere lo stesso fatto
  due volte: due istruzioni, una verita');
- **terminazione su un ciclo** `a=b, b=c, c=a` — dove un'implementazione ingenua
  gira all'infinito;
- nessun tipo inventato senza vincoli;
- variabili fuori range non vanno in panic (input malformato dal generatore, che
  gira su tipi recuperati da binari non fidati);
- `class_count` non supera il numero di variabili.

Tutte verdi: l'unificatore **ha** le proprieta' che deve avere. E' un risultato
negativo utile — ora e' verificato invece che sperato.

- 4 crate: **2079** passati, 0 falliti (2069 -> 2079). Build senza warning.

## 2026-07-29 — Iterazione 34 (T26: degradazione sicura, e un `Default` trappola)

### La proprieta' cercata

La scala e' `size -> primitive -> pointer -> struct -> array -> vtable ->
signature`, e ogni piolo poggia sul precedente. La proprieta' che rende
affidabile l'insieme non e' "ogni piolo e' giusto", ma:

> quando l'evidenza sotto e' ambigua, un piolo deve riportare **meno**, non
> indovinare **di piu'**.

E' il tema di ogni difetto reale trovato in questa sessione. Un parametro
fantasma su `strdup`, un nome rust-stdlib su una funzione C, un `bool` collassato
in un layout che non ha: nessuno fallisce rumorosamente. Compilano tutti, sembrano
sani, e corrompono chi li consuma. Un `Unknown` e' visibilmente inutile; un tipo
sbagliato e' invisibilmente sbagliato.

### Il difetto trovato: `#[derive(Default)]` fabbricava struct dal nulla

Due dei 11 test sono falliti subito. Causa:
`StructRecoveryEngine` derivava `Default`, ottenendo `pointer_width: 0` e
`min_access_count: 0`. Conseguenze, entrambe silenziose:

- `min_access_count == 0` faceva restituire `Some` a `recover_for` per **ogni**
  variabile, osservata o no — uno struct a zero campi presentato come risultato.
  "Questo e' uno struct senza campi" e' un'affermazione; l'assenza di evidenza
  non dovrebbe produrre affermazioni.
- `pointer_width == 0` rendeva `looks_like_pointer` incapace di scattare: il
  piolo "pointer" era **morto** in ogni engine costruito cosi'.

I due costruttori nominati (`new_64bit`, `new_32bit`) mettono valori sensati
(1, 8/4). Il derive era una trappola, non una comodita': `Default::default()` e'
il modo ovvio di costruire il tipo. Ora `Default` delega a `new_64bit()`.

### 11 test di degradazione

Nessun accesso -> nessuno struct; una base mai osservata non eredita il layout di
un'altra; accessi sovrapposti **segnalati** invece che risolti in silenzio (union?
bitfield? due struct sullo stesso puntatore? l'evidenza non lo dice); i buchi
marcati come padding invece che riempiti con campi inventati; `total_size` mai
oltre l'accesso piu' lontano — un size gonfiato lascerebbe leggere oltre
l'oggetto, che e' il difetto `count_set_flags` gia' documentato nel repo;
`Unknown` non risponde a domande strutturali; `*Unknown` resta tale (collassarlo
perde l'unico fatto noto, promuoverlo a `*u8` ne inventa uno); e il recupero e'
indipendente dall'ordine degli accessi.

- 4 crate: **2090** passati, 0 falliti (2079 -> 2090). Build senza warning.

## 2026-07-29 — Iterazione 35 (i fratelli del bug: 6 altri `Default` trappola)

### Cercati i fratelli, invece di fermarsi al caso singolo

Il `derive(Default)` trovato nell'iterazione 34 era un **pattern**, non un caso
isolato. In questa sessione ogni difetto ne aveva altri (11 -> 16 CRC, 4 -> 7
writer di header, 2 -> 3 encoder di trie), quindi ho cercato sistematicamente
gli struct con `#[derive(..., Default)]` e campi soglia.

**Trovati altri sei**, ognuno con un costruttore sensato e un `Default` che azzera:

| tipo | campo | `new()` | `Default` derivato |
|---|---|---|---|
| `FlirtEngine` | `min_pattern_len` | 4 | 0 |
| `ObjFileParser` | `min_func_size` | 4 | 0 |
| `FunctionExtractor` | `max_func_size` | 65536 | **0** |
| `PrologueSampler` | `min_occurrences` | 2 | 0 |
| `SigOptimizer` | `min_exact_bytes` | 4 | 0 |
| `BatchApply` | `min_confidence` | 0.5 | 0.0 |

### Perche' uno zero non e' un default neutro

Per una **soglia** lo zero non e' "nessuna preferenza", e' una configurazione
degenere che disattiva il controllo che il campo esiste per imporre:

- `min_confidence: 0.0` accetta ogni match, per quanto debole;
- `min_pattern_len: 0` accetta un pattern di zero byte — che combacia **ovunque**;
- `max_func_size: 0` e' il peggiore: un *massimo* di zero **rifiuta tutto**, e
  l'estrattore produce silenziosamente niente.

Nessuno fallisce rumorosamente. Producono output plausibile, vuoto o troppo pieno.

### Consegnato

Tutti e sette (i sei piu' `StructRecoveryEngine`) ora delegano al costruttore
nominato. 7 test in `default_matches_named_constructor.rs` che verificano
**sia** l'uguaglianza `Default == new()` **sia** che la soglia sia > 0 — la
seconda serve perche' se qualcuno cambiasse anche `new()` a zero, la prima
passerebbe comunque.

- 4 crate: **2097** passati, 0 falliti (2090 -> 2097). Build senza warning.

## 2026-07-29 — Iterazione 36 (misurato il dubbio che avevo dichiarato)

Chiudendo l'iterazione 35 avevo scritto: *"non ti dico che erano sette bug vivi;
ti dico che erano sette trappole armate"* — e che non l'avevo misurato. Misurato.

| tipo | `default()` in produzione | `default()` nei test | `::new()` in produzione |
|---|---|---|---|
| `StructRecoveryEngine` | **0** | 10 | 7 |
| `FlirtEngine` | **0** | 2 | 10 |
| `ObjFileParser` | **0** | 2 | 8 |
| `FunctionExtractor` | **0** | 2 | 6 |
| `PrologueSampler` | **0** | 2 | 3 |
| `SigOptimizer` | **0** | 2 | 3 |
| `BatchApply` | **0** | 1 | 4 |

### Verdetto: erano trappole dormienti, non bug attivi

**Zero call site in produzione.** Il codice di produzione costruisce sempre con
`::new()`, che ha i valori giusti. Il fix dell'iterazione 35 previene un danno
futuro e migliora la fedelta' dei test — **non** ha corretto un difetto in
produzione, e sarebbe scorretto contarlo come tale.

### Il danno che invece c'era davvero

I test che usavano `default()` esercitavano una configurazione degenere
(`pointer_width: 0`, soglie a 0) che **non si verifica mai in produzione**.
Erano test con meno valore di quanto sembrasse: verificavano un engine
configurato come nessuno lo configura. Dopo il fix esercitano la configurazione
reale — la suite resta verde, quindi nessuno di essi dipendeva dai valori nulli.

E' anche il motivo per cui il difetto e' emerso: il mio test di degradazione
sicura ha usato `default()` ed e' fallito. Un difetto trovato tramite un test che
lo stava subendo.

- 4 crate: **2097** passati, 0 falliti (invariato: nessun cambiamento di codice
  in questa iterazione, solo misura).

## 2026-07-29 — Iterazione 37 (T3c: la finestra CRC e' mascherata in tre modi)

### Tre comportamenti per un campo

| sito | i byte mascherati sono… | lunghezza buffer |
|---|---|---|
| `flirt_gen::CrcTail::compute` (generatore) | **scartati** | piu' corta |
| `flirt_apply::compute_flirt_crc` (validatore) | **azzerati** | invariata |
| `FlirtScanner::scan_fast` (il percorso realmente usato) | **non mascherati** | invariata |

L'**algoritmo** e' stato unificato nelle iterazioni 2-3; l'**input** no. Due
qualsiasi di queste regole producono byte diversi, quindi CRC diversi, ogni volta
che una rilocazione cade nella finestra CRC.

### E il campo `crc_length` significa due cose diverse

Il generatore memorizza `stable.len()` — **quanti byte ha effettivamente
hashato** dopo aver scartato i mascherati. Lo scanner legge
`data[start..start+crc_len]` — **quanti byte contigui hashare**. Coincidono solo
se non c'era niente da mascherare.

### La meta' mancante di una misura precedente

Nell'iterazione 21 avevo misurato che il 74.1% del database ha un CRC ma solo
**2 match su 240** venivano da firme con CRC, e l'avevo attribuito a "code che
divergono correttamente". Misure a supporto dell'altra spiegazione:

- 49 780 pattern con CRC, con `crc_length` sparso su 16, 1, 4, 7, 2, 6… —
  coerente con un **conteggio di sopravvissuti**, non con una finestra fissa;
- **31 533 pattern (47%) contengono wildcard**.

Messe insieme, e' un caso forte che le firme con CRC vengano rifiutate **per
costruzione** invece che sulla base dell'evidenza.

**Non e' una prova.** Chiuderla richiede una run end-to-end generate->scan su una
funzione con una rilocazione dentro la finestra CRC — cioe' T14. L'ho scritto nel
doc del test invece di presentare l'ipotesi come conclusione.

### 6 test

Divergenza fra le tre regole; il caso in cui **coincidono** (nessun byte
mascherato) — ed e' il motivo per cui il difetto e' invisibile su funzioni
semplici; il caso in cui azzerare e' un no-op perche' il byte era gia' zero, che
renderebbe un corpus accidentalmente "sano"; e l'incompatibilita' fra i due
significati di `crc_length`.

- 4 crate: **2103** passati, 0 falliti (2097 -> 2103).

### Aperto / da non dimenticare

- **T1 è un possibile bug di compatibilità, non un dettaglio di test.** flair
  `crc16.cpp` potrebbe ritornare 0 per input vuoto. Va verificato contro un
  `.sig` reale prima di dichiarare la compatibilità IDA.
- Nessun benchmark, nessun fuzz, nessun test end-to-end gen→apply esiste ancora:
  i 1644 test sono quasi tutti unit test su singole funzioni. Verde ≠ corretto.

## 2026-07-29 — Iterazione 38 (T14: il round-trip chiude T3c — misurato, non piu' ipotizzato)

**L'ipotesi dell'iterazione 37 e' ora un fatto misurato.** Ieri avevo scritto,
di proposito, che le tre regole di mascheratura del CRC erano "un forte indizio,
non una prova", e che chiuderla richiedeva una run end-to-end. Fatta.

`examples/self_match_experiment.rs`: archivio reale → harvest col generatore
vero → `.sig` → scan **sugli stessi byte da cui i pattern provengono**. Non
esiste input piu' favorevole; una firma che non ritrova il proprio codice e'
rotta senza appello.

Misurato su `C:\msys64\mingw64\lib\libz.a` (15 membri, 15 oggetti, 132 pattern,
26 con wildcard):

| sottoinsieme | auto-riconoscimento |
|---|---|
| tutti i pattern | 86/132 (**65.2%**) |
| senza wildcard | 83/106 (78.3%) |
| con wildcard | 3/26 (**11.5%**) |
| tutti, campo CRC azzerato | 128/132 (**97.0%**) |
| con wildcard, CRC azzerato | 22/26 (**84.6%**) |

**Azzerare un solo campo recupera 42 delle 46 funzioni perse.** Il CRC
memorizzato non e' quello che lo scanner ricalcola, quindi rifiuta invece di
confermare. Non e' un difetto di matching dei wildcard: i wildcard sono
semplicemente dove si concentrano le rilocazioni, quindi i byte mascherati,
quindi i CRC divergenti.

**Un errore commesso e corretto, degno di nota perche' e' lo stesso difetto che
il progetto insegue.** Il primo `tests/self_match_round_trip.rs` che ho scritto
riproduceva a mano il calcolo CRC del generatore per restare ermetico. Il
modello era sbagliato — ignorava `crc_offset`, quindi costruiva la finestra nel
posto sbagliato — e il test di controllo falliva. Stavo misurando il mio modello,
non il crate. Riscritto: ora usa solo `SigWriter` e `FlirtScanner` reali e fissa
il meccanismo (un CRC irriproducibile trasforma un match in un miss), mentre le
percentuali restano nell'example, dove serve un archivio vero. Un modello
plausibile di un componente non e' il componente.

**Non concluso, e detto esplicitamente:**
- i 4/132 che falliscono anche senza CRC sono un difetto separato, non
  attribuito;
- *quale* delle tre regole di mascheratura sia quella giusta resta indecidibile
  senza un `.sig` prodotto da flair (T1/T15). So che divergono e quanto costano;
  non so ancora quale sia conforme a IDA;
- T14 e' a meta': il round-trip prova che le firme funzionano su se stesse, non
  che ritrovino la stessa funzione compilata in un *altro* binario. Quella meta'
  resta aperta.

**Test: 2106 passati, 0 falliti** sui 4 crate, release. +3 rispetto ai 2103
dell'iterazione 37.

**Le due decisioni per l'utente restano aperte** (sollevate in piu' report,
mai risposte, e non le prendo da solo):
1. soglia 16 come default (misurato: 5071 → 0 falsi positivi su binari non-Rust,
   precisione 64.3% → 88.2%);
2. cancellare le 935 righe morte (`flirt_matcher_v2` 786 + `signature_matcher_new`
   149) — sono `pub`, quindi e' un breaking change.

## 2026-07-29 — Iterazione 39 (T3b: l'ultimo algoritmo CRC in gara, chiuso per misura)

**Correzione a un numero pubblicato ieri.** L'iterazione 38 riporta "2106 test
passati": è sbagliato, l'avevo sommato a occhio dalla tabella `uniq -c`. Il
totale reale, estratto in due modi indipendenti, è **1965** in questa iterazione
(che include +4 test nuovi), quindi ~1961 ieri. Le percentuali del round-trip
dell'iterazione 38 restano valide: quelle erano lette dall'output, non sommate.

**T3b chiuso.** Era fermo da diverse iterazioni con una motivazione esplicita:
`pattern_optimizer` calcolava il CRC con `arc` invece di `flirt_tail`, ma non
era dimostrato che quel valore finisse nello stesso campo, e cambiarlo a intuito
sarebbe stato un tiro a indovinare. Misurato ora:

- **È lo stesso campo, per costruzione**: `OptimizedPattern` porta la terna
  `(crc_offset: u16, crc_len: u8, crc: u16)`, identica al leaf di un `.sig`, e
  il generatore reale `PatternGenerator::generate` riempie quella terna con
  `crc16_flirt` sulla finestra che parte subito dopo i byte iniziali.
- **Non ci arriva mai, di fatto**: `pattern_optimizer` è dichiarato in `lib.rs`
  e importato da **nessun** modulo del workspace. Nessun `.sig` ha mai
  trasportato un valore prodotto lì.

Quindi il difetto era reale ma latente: il terzo algoritmo per il campo tail CRC
sopravvissuto a T3, più un commento che dichiarava `ARC` "FLIRT standard" —
falso in questo stack. Corretti entrambi.

**Neutralità provata, non assunta.** Il round-trip di T14 rieseguito dopo il
cambio dà righe identiche: 132 pattern, 86 (65.2%) / 83 di 106 (78.3%) /
3 di 26 (11.5%) / 128 (97.0%) / 22 di 26 (84.6%). È la stessa forma di
argomento del `diff -rq` fra snapshot: una cifra assoluta non proverebbe nulla,
l'identità riga per riga sì.

Il test `window_selection_does_not_depend_on_the_polynomial` merita una nota: il
`CrcWindowSelector` usa il CRC solo per contare valori distinti, quindi cambiare
polinomio potrebbe in linea di principio cambiare *quale* finestra viene scelta.
Verificato che non lo fa sul corpus del test — se lo facesse, il cambio non
sarebbe neutro e andrebbe rimisurato invece che dichiarato.

**Test: 1965 passati, 0 falliti** sui 4 crate, release. Build release pulita.

**Le due decisioni per l'utente restano aperte e non le prendo da solo:**
soglia 16 come default (5071 → 0 falsi positivi misurati), e cancellazione delle
935 righe morte (`pub`, quindi breaking change).

## 2026-07-29 — Iterazione 40 (T39 confutato; e ho spedito un rosso dichiarandolo verde)

### Prima: la correzione, perche' invalida quanto ho pubblicato ieri

**L'iterazione 39 e' stata pubblicata "1965 test, 0 falliti". Era falso su
entrambi i numeri.** Il mio cambio `arc` → `flirt_tail` in `pattern_optimizer`
aveva rotto un unit test (`test_crc16_known`, che fissava a costante `0xBB3D`,
il check value di ARC), e non me ne sono accorto per due difetti del *comando di
misura*, non del codice:

1. `awk -F'[ ;]' '{f+=$6}'` sommava un campo vuoto: il "0 falliti" non era una
   misura, era un artefatto dello split. La seconda estrazione "indipendente"
   che avevo lanciato per confermare estraeva **solo** i passed, quindi non
   poteva contraddire la prima.
2. `cargo test` **interrompe i target rimanenti** al primo fallimento, quindi
   anche il 1965 era un conteggio troncato, non il totale.

Totale reale, con `--no-fail-fast` e due estrazioni che stavolta contano
entrambe le colonne: **2115 passati, 0 falliti, 0 target FAILED**.

Ho verificato due volte il numero sbagliato e zero volte quello che contava.
Confermare una cifra con un secondo comando che misura la stessa cosa non e'
una verifica indipendente.

**Riparato prima di procedere**, come richiede il loop: `test_crc16_known` ora
fissa il check value di MCRF4XX (`0x6F91`) **e** l'accordo con
`rustre_flirt::crc::flirt_tail`. Due pin che devono concordare: la costante da
sola andrebbe alla deriva se `crc16` venisse ripuntato, la delega da sola
passerebbe anche con la primitiva sbagliata. Che quel test fissasse la costante
di ARC e' esattamente perche' T3b e' sopravvissuto a T3: certificava il difetto.

### T39 — confutato, nessuna modifica necessaria

`TypeConstraint::Deref { .. } => {}` a `rustre-analysis-type/src/lib.rs:437`
sembrava un vincolo accettato e poi buttato — il modo di fallire tipico di
questo progetto (una risposta sicura e sbagliata invece di un `Unknown`).
Non lo e': Deref e' gestito da un pass dedicato dopo la risoluzione degli
`Equal`, iterato a punto fisso, e `solve_checked` riporta la non-convergenza.

Verificato **eseguendo il solver**, non leggendo il commento: un commento puo'
descrivere un'intenzione che il codice non implementa piu'. 5 test misurano che
l'informazione sopravvive davvero — puntatore derivato, indipendenza
dall'ordine, Deref prima del pointee, catena a due livelli non appiattita,
ciclo riportato come non-convergente invece che troncato in silenzio.

I test stanno in `typerecov` (che dipende da `rustre-analysis-type`): il
comportamento resta fissato dal lato consumatore senza modificare un crate
fuori dai quattro.

**Test: 2115 passati, 0 falliti** sui 4 crate, release. Build release pulita.

Le due decisioni per l'utente restano aperte (soglia 16; 935 righe morte).

## 2026-07-29 — Iterazione 41 (T37: da "52 duplicati" a una lista azionabile)

**Il problema con 52 era che non si poteva agire.** Il numero dice che il debito
esiste, non quali istanze possono fare danno, e "sistemane 52" e' esattamente il
refactor a tappeto non verificato che il loop vieta. Serviva una classifica.

Misurato con `tests/duplicate_types_ranked_by_divergence.rs`, confrontando gli
insiemi di campi/varianti pubblici di ogni dichiarazione omonima:

| classe | conteggio |
|---|---|
| nomi duplicati | 52 |
| **divergenti** (campi diversi) | **50** |
| congruenti (stessi campi) | 2 |

**E 50 non sono 50 difetti — questo va detto, non sottinteso.** Divergere e'
necessario ma non sufficiente perche' ci sia danno: `Confidence` e' un enum in
typerecov e una struct in `flirt_applicator`; `CollisionResolver` e' una
strategia di dedup in un crate e una tabella di pesi in un altro. Sono
collisioni di nome fra moduli, che Rust gestisce e che nessuno puo' scambiare.
Il sottoinsieme dannoso e' quello che modella lo **stesso concetto**, dove un
valore, un layout serializzato o del codice possono attraversare.

**Il bersaglio migliore che la scansione ha fatto emergere** non lo avevo in
lista: `CoffSection` e `CoffSymbol` sono dichiarati **due volte dentro lo stesso
crate**, `rustre-flirt-gen/library_scanner.rs` e
`rustre-flirt-gen/pattern_extractor.rs`. Due decoder dello stesso formato COFF,
in disaccordo perfino sull'ortografia dei campi (`section_num` vs
`section_number`, `type_field` vs `type_`). Una collisione fra crate puo' essere
coincidenza; due decoder dello stesso formato in un crate no. Ed e' il bersaglio
giusto perche' e' limitato, ha ground truth (il layout COFF pubblicato) e la
neutralita' e' misurabile col round-trip di T14.

**Un errore mio, colto dal test che lo conteneva.** Avevo scritto il gate con
`BASELINE = 40`, una stima a intuito: la misura ha dato 50 e il test e' fallito
subito. Corretto al valore misurato. E' la stessa regola di ieri vista da un
altro lato — una costante scritta a intuito non e' una baseline; l'unico motivo
per cui non e' diventata un numero pubblicato e' che l'assertion puntava per
caso nel verso giusto.

**Limiti dichiarati della misura** (nel doc del test, non solo qui): e' una
scansione del sorgente, confronta i *nomi* dei campi e non i loro tipi, legge le
struct a soli campi privati come insieme vuoto, e non distingue i `#[cfg]`.
Ognuno di questi fa **sotto**stimare i divergenti — direzione sicura per un
numero usato per decidere cosa sistemare, ma "congruente" qui significa "non
dimostrato divergente", mai "dimostrato identico".

**Test: 2120 passati, 0 falliti, 0 target FAILED** sui 4 crate, release, con
`--no-fail-fast` e il conteggio di entrambe le colonne. Build release pulita.

Le due decisioni per l'utente restano aperte (soglia 16; 935 righe morte).

## 2026-07-29 — Iterazione 42 (T37: il primo bersaglio era un bug, non debito)

Preso il bersaglio che l'iterazione 41 aveva indicato: `CoffSection`/`CoffSymbol`
dichiarati due volte dentro `rustre-flirt-gen` (`library_scanner.rs` e
`pattern_extractor.rs`). L'ipotesi era "duplicazione da riordinare". Misurando,
e' venuto fuori un difetto di correttezza.

**I due decoder davano nomi diversi per gli stessi byte.**

| decoder | regola sul nome |
|---|---|
| `library_scanner` | tronca al primo NUL |
| `pattern_extractor` | `trim_end_matches('\0')` — strippa i NUL **finali** |

Un nome COFF e' un campo di 8 byte NUL-**padded**, quindi finisce al primo NUL.
Misurato sugli stessi byte `.text\0AB`: `".text"` contro `".text\0AB"` — una
`String` con un NUL interno e spazzatura in coda.

**Perche' era invisibile:** le due regole coincidono quando il padding e' tutto
zeri, che e' quello che emette un linker. Nessun controllo a campione su un
oggetto reale lo avrebbe trovato. Ma `flirt-gen` ingerisce archivi `.lib` di
terze parti — e' il motivo per cui in questo progetto esistono le suite su input
ostile — e lo stesso difetto era anche in `parse_symbols`, dove il nome corto di
un simbolo diventa **il nome di una firma emessa**.

Corretto con un helper unico `coff_short_name`, che tronca al primo NUL in
entrambi i siti. 5 test in `tests/the_two_coff_decoders_agree.rs`, scritti e
fatti fallire **prima** della correzione (2 rossi su 5: divergenza e NUL
interno), poi verdi.

**Neutralita' misurata, non assunta:** round-trip di T14 rieseguito dopo la
correzione, righe identiche (132 pattern; 86 / 83 di 106 / 3 di 26 / 128 /
22 di 26). Era la previsione — su oggetti emessi da un linker le due regole
coincidono — ma prevedere non e' misurare.

**Non fatto, e detto:** i due *tipi* restano due. Questa iterazione li ha fatti
concordare, non unificati. Quando si unificheranno, tenere quello di
`pattern_extractor`: e' il superset (ha `pointer_to_relocations`,
`number_of_relocations`) e usa i nomi di campo pubblicati PE/COFF, mentre
l'altro li abbrevia (`virtual_addr`, `raw_size`).

**Test: 2125 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne contate. Build release pulita.

Le due decisioni per l'utente restano aperte (soglia 16; 935 righe morte).

## 2026-07-29 — Iterazione 43 (T37: `SigHeader` x5, e il layout sbagliato era ancora vivo)

Secondo bersaglio same-concept, stesso metodo del COFF: codifica una volta col
codec canonico, decodifica con tutti, confronta. Ha trovato un altro bug vero.

**`rustre_flirt::parse_sig_header` era ancora sul layout sbagliato.** Metteva
`alt_ctype_crc` e `n_functions` **dopo** il nome a lunghezza variabile; il
layout pubblicato li ha a offset fissi 35 e 37, con `pattern_size` a 41 e solo
il nome variabile, a 43.

Misurato su un header prodotto dal codec canonico con nome
`"libz mingw64 build"`:
- nome letto: 8 byte di spazzatura seguiti dal nome troncato — iniziava a
  offset 35 invece di 43;
- lunghezza header dichiarata: **41 invece di 43**, quindi tutto cio' che segue
  veniva letto disallineato.

**Non e' codice morto:** `flirt_database` parsa blob reali attraverso
`FlirtSigFile::parse`, che chiama questo parser.

T27 aveva corretto il layout "su entrambi i lati". Questo terzo sito era stato
mancato — e il suo unit test, `parse_sig_header_valid_v9_min`, costruiva a mano
lo **stesso** layout sbagliato che il parser leggeva, quindi passava e lo
certificava. E' la terza volta in questa sessione che un test a offset fissi
conferma il difetto che avrebbe dovuto cogliere.

Correzione: `parse_sig_header` delega a `sig_header::SigFileHeader::decode`, e
il test ora costruisce i byte **col codec canonico**, cosi' non puo' concordare
con un parser derivato. 5 test in
`rustre-flirt-apply/tests/all_sig_header_decoders_agree.rs`, scritti e fatti
fallire prima (2 rossi su 5).

**Cosa NON ho toccato, e perche'.** Avevo inizialmente fatto rifiutare il ramo
legacy `0x54 0x4A` come "layout non verificato". Poi ho misurato che
`parse_sig_header` sta su un percorso vivo, e ho ritirato quella parte: cio' che
ho misurato sbagliato e' il layout **IDASGN**, non quello. Il ramo legacy usa la
stessa forma, quindi e' probabilmente sbagliato anche li' — ma "probabile" non
e' una misura, non c'e' un `.sig` di flair nel repo per verificarlo, e cambiare
cio' che un percorso vivo accetta sulla base di un'intuizione avrebbe barattato
una correzione misurata con un rischio non misurato. Isolato in
`parse_legacy_tj_header` con il perche' scritto sopra; appartiene a T1/T15.

**Nota di ambiente:** durante l'iterazione il crate vicino `rustre-demangle` era
rotto da edit concorrenti (`split_scope_at_depth_zero(qualified_name)` invece di
`&qualified_name`). Ho ritentato invece di correggerlo subito, come dice
CLAUDE.md, e nel frattempo l'ha sistemato chi ci stava lavorando. Non ho toccato
quel crate.

**Test: 2130 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne contate. Build release pulita.
**Neutralita' misurata:** round-trip di T14 identico riga per riga.

Le due decisioni per l'utente restano aperte (soglia 16; 935 righe morte).

## 2026-07-30 — Iterazione 44 (T29/T37: test scritto, VERIFICA PENDENTE — nessun numero)

**Non pubblico alcun risultato in questa iterazione: non ho potuto eseguire i
test.** Il lock di build era saturo. Tre tentativi da ~10 minuti ciascuno, tutti
fermi su `Blocking waiting for file lock on build directory`; misurati **31
processi `cargo`** attivi di agenti concorrenti, il piu' vecchio avviato oltre
quattro ore prima. Non li ho terminati: sarebbe stato sabotare il lavoro di
qualcun altro per far girare il mio.

Questo e' il caso che la nota in memoria prescrive: dichiarare la verifica
pendente invece di pubblicare un verde vecchio. Quindi **TODO.md non e' stato
spuntato** e non compare nessuna cifra nuova.

### Cosa e' stato scritto (non verificato)

`rustre-flirt-apply/tests/flirt_pattern_crosses_the_type_boundary.rs`, 5 test sul
terzo bersaglio same-concept di T37: i due `FlirtPattern`.

| | `rustre-flirt` | `rustre-flirt-apply` |
|---|---|---|
| byte | `initial_bytes: Vec<PatternByte>` | `bytes: Vec<Option<u8>>` |
| inizio finestra CRC | **implicito**: dopo i byte iniziali | `crc_offset: u16` |
| lunghezza finestra | `crc_length: u8` | `crc_len: u16` |
| nomi | `names: Vec<FlirtName>` | `name` + `public_names` + `local_names` |

A differenza delle collisioni di nome innocue contate nell'iterazione 41, qui i
**valori attraversano davvero**: il generatore costruisce il primo tipo,
`SigWriter` lo serializza, `FlirtScanner` ricostruisce il secondo. Il `.sig` e'
il ponte fra due modelli che non concordano.

L'ipotesi che i test devono decidere: l'inizio della finestra CRC e' implicito da
un lato ed esplicito dall'altro, quindi se la traversata non lo ricostruisce lo
scanner calcola il CRC su byte diversi da quelli su cui e' stato generato. Se
confermata, sarebbe una spiegazione candidata per parte del divario 65.2% → 97.0%
gia' misurato in T3c. **Ipotesi, non risultato**: senza esecuzione non so nemmeno
se i test compilano.

### Prossima iterazione

Rieseguire, nell'ordine: quel file di test, poi build+suite completa
(`--no-fail-fast`, entrambe le colonne), poi il round-trip di T14 per la
neutralita'. Solo dopo si puo' scrivere un numero.

## 2026-07-30 — Iterazione 45 (verifica pendente sbloccata: due bug e una decisione)

Il lock si e' liberato e ho eseguito la verifica che l'iterazione 44 aveva
lasciato pendente. I test **non compilavano** (`FlirtScanner` non espone
`patterns()`), poi sono falliti tutti e cinque, e ciascun fallimento era
informativo. Nessuno dei numeri qui sotto e' quello che avevo ipotizzato ieri.

### 1. `load_sig_file` recuperava 1 firma su 3 (bug, corretto)

Misurato con `examples/two_sig_readers.rs` su un `.sig` di 169 byte contenente
3 pattern, scritto da `rustre_flirt_gen::SigWriter`:

| lettore | firme recuperate |
|---|---|
| `FlirtScanner::from_sig_bytes` | 3 |
| `load_sig_file` | **1** |

Causa: `load_sig_file` calcolava l'inizio del trie con il layout vecchio (nome a
offset 32 anziche' 43, piu' due byte di `ctypes_crc16` da saltare) — sfasato di
9 byte, quindi il decode si desincronizzava subito. **Quarto sito** trovato sul
layout header sbagliato, dopo i tre dell'iterazione 43. E' su un percorso reale:
`load_auto` lo chiama.

Corretto delegando a `SigFileLoader`, lo stesso lettore del percorso che
funziona, invece di tenere allineati a mano un secondo parser di header e un
secondo decoder di trie. **Dopo: 3 su 3.**

Il test che lo copriva, `test_merge_sig_dir_loads_sig_files`, costruiva la
fixture a mano — il suo doc comment la chiamava esplicitamente "minimal
**legacy-header** .sig blob that `load_sig_file` parses". Scritta per combaciare
con l'errore del parser, quindi passava. Ora la fixture la produce `SigWriter`.
E' la quarta volta in questa sessione.

### 2. Il container `.sig` non rappresenta i wildcard (difetto, non corretto)

`SigWriter::build` prende il prefisso con `take_while(PatternByte::Exact)`,
commentato "so no spurious 0x00 wildcards enter the trie". Le chiavi del trie
sono byte concreti: non c'e' posto per un "don't care". Misurato: un pattern di
16 byte con wildcard a 3..7 attraversa come pattern di **3 byte**, senza
wildcard. Niente si corrompe, ma una firma di 3 byte non vale quasi nulla, e la
perdita e' silenziosa.

**Rilevante per T3c, e corregge cio' che quella misura poteva dire.** Il
round-trip aveva misurato i pattern con wildcard all'11.5%, e non poteva
distinguere "wildcard conservato" da "wildcard scartato": scansiona gli stessi
byte da cui il pattern viene, dove un prefisso di byte esatti combacia
ugualmente. Questo test lo distingue, e la risposta e' scartato.

### 3. `crc_offset` ha due convenzioni — decisione, non difetto

Avevo scritto il test aspettandomi `crc_offset == prefix`. Ha fallito, e
**l'errore era mio**: `scan_fast` legge quel campo come RELATIVO alla fine del
pattern (`offset + pat_len + crc_offset`), quindi 0 e' corretto la'.
Ma il codice porta gia' una nota `KNOWN INCONSISTENCY` in quel punto:
`Disambiguator::check_crc` lo legge come ASSOLUTO dall'inizio del match, e i
produttori in `ida_sig_compat` lo scrivono assoluto (`bytes.len()`). Due su tre
dicono assoluto; la traversata produce quello relativo.

Fissato **come misurato**, non "corretto": ogni convenzione ha i suoi test verdi,
e sceglierne una e' una decisione di semantica voluta, non un bug con una sola
risposta giusta.

### Cosa sopravvive intatto

Nome e `crc_length` (u8 -> u16: allargamento, non puo' perdere valori).

**Test: 2135 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.
**Neutralita' misurata:** round-trip di T14 identico riga per riga
(132; 86 / 83 su 106 / 3 su 26 / 128 / 22 su 26).

### Decisioni aperte per l'utente (ora tre)

1. soglia 16 come default (5071 -> 0 falsi positivi misurati);
2. cancellare le 935 righe morte (`pub`, breaking change);
3. **quale convenzione per `crc_offset`**: relativa (scan_fast) o assoluta
   (Disambiguator + ida_sig_compat). Non la scelgo da solo.

## 2026-07-30 — Iterazione 46 (T14 seconda meta': misurato cross-binario. Test NON verificato)

**Stato onesto in due parti.** Le misure sotto sono reali: `examples/cross_binary_match.rs`
e' stato eseguito (exit 0) e i numeri vengono dal suo output. Il file di test
scritto dopo per fissarle, `tests/cross_binary_specificity.rs`, **non e' stato
eseguito**: il lock di build si e' saturato (due tentativi da ~10 minuti). Non
spunto T14 e non dichiaro nulla di verde.

### La misura che il round-trip non poteva fare

Firme da `libmingwex.a` (293 membri, 293 oggetti, **522 pattern**), scansionate su
un binario mingw del corpus e su un binario Go che quelle funzioni non puo'
contenere. Dei 522: **151 troncati** dal container per via di un wildcard,
**27 ridotti a meno di 8 byte**.

| sottoinsieme | target (sample1_c) | estraneo (sample4_go) |
|---|---|---|
| tutti (522) | 4 | **5** |
| solo integri (371) | 1 | **0** |
| solo troncati (151) | 3 | 5 |
| solo ridotti <8 byte (27) | 3 | 5 |

**Hanno combaciato piu' nomi sul binario ESTRANEO che su quello legittimo**, e
tutti i falsi positivi vengono dai troncati: 27 pattern tagliati corti dalla
perdita dei wildcard li producono tutti. I 371 integri: zero.

Ne segue una lettura che non voglio addolcire: i 3 match "sul target" dal gruppo
troncato sono con ogni probabilita' anch'essi falsi positivi, essendo chiavi di
3-7 byte. Il recall reale e' circa **1 su 522**, non 4.

### Sweep della soglia — dato nuovo e indipendente sulla decisione aperta

| `min_bytes_without_crc` | target | estraneo |
|---|---|---|
| 0 | 4 | 5 |
| 4 | 1 | 2 |
| **8** | 1 | **0** |
| 16 | 1 | 0 |
| 24 | 0 | 0 |

E' un secondo corpus, indipendente da quello su cui la soglia era stata misurata
prima (rust-stdlib: 5071 falsi positivi a 0, zero a 16). Qui **8 basta gia'** e
**16 non costa nulla in piu'**, mentre 24 distrugge l'unico match vero rimasto.
Questo rafforza la scelta di 16 come default, con margine.

### Da fare domani, in quest'ordine

1. eseguire `cargo test --release -p rustre-flirt-apply --test cross_binary_specificity`
   (3 test, saltano se mingw o il corpus mancano) — **e' la verifica pendente**;
2. build + suite completa (`--no-fail-fast`, entrambe le colonne). Ultimo verde
   noto: **2135 passati, 0 falliti** (iterazione 45);
3. round-trip di T14 per la neutralita';
4. solo dopo, spuntare T14 e scrivere i numeri.

## 2026-07-30 — Iterazione 47 (verifica pendente sciolta: T14 COMPLETO)

Il lock si e' liberato ed e' stata eseguita la verifica che l'iterazione 46 aveva
lasciato in sospeso. **Tutto verde, e i numeri di ieri reggono.**

- `cargo test --release -p rustre-flirt-apply --test cross_binary_specificity`:
  **3 passati, 0 falliti**. I test non hanno saltato: mingw e il corpus sono
  presenti, quindi hanno davvero misurato.
- Build release dei 4 crate: pulita.
- Suite completa (`--no-fail-fast`, entrambe le colonne):
  **2138 passati, 0 falliti, 0 target FAILED** (+3 rispetto ai 2135
  dell'iterazione 45).
- Round-trip di T14 per la neutralita': identico riga per riga
  (132 pattern; 86 / 83 su 106 / 3 su 26 / 128 / 22 su 26).

**T14 e' completo** e spuntato in TODO.md. Le due meta':
1. round-trip (iterazione 38) — ha provato T3c;
2. cross-binario (iterazioni 46-47) — ha misurato quello che il round-trip non
   poteva vedere.

Il risultato che conta, ora fissato da test verdi e non piu' solo da un example:
su 522 firme da `libmingwex.a`, **4 nomi sul binario target e 5 su un binario Go
che quelle funzioni non puo' contenere**. Tutti i falsi positivi vengono dai 151
pattern troncati dalla perdita dei wildcard, e i 371 integri ne producono zero.
Quindi il recall reale e' **~1 su 522**, non 4.

Sweep della soglia, confermato: 0 -> (4,5), 4 -> (1,2), **8 -> (1,0)**,
16 -> (1,0), 24 -> (0,0).

**Loop riarmato** a 60s (job `74e64923`, ricorrente, sessione-only).

Le tre decisioni per l'utente restano aperte: soglia 16 come default, le 935
righe morte, e la convenzione di `crc_offset`.

## 2026-07-30 — Iterazione 48 (T4b chiuso: i writer `.pat` sono write-only)

T4b era descritto cosi': "i 4 parser `.pat` accettano 3 formati diversi, un
`.pat` scritto per una parte dello stack non e' leggibile da un'altra". Vero, ma
lasciava senza risposta la domanda piu' affilata: **e' leggibile da qualcuno?**

Misurata la matrice completa writer x parser con
`examples/pat_writer_parser_matrix.rs`, su 3 pattern (esatto, con wildcard, con
CRC):

| writer \ parser | `apply::pat_parser` | `flirt::pat_v2` | `flirt::parse_pat_text` |
|---|---|---|---|
| `gen::pat_file_writer` | ERR | 0 | 0 |
| `flirt::signature_writer` | ERR | 0 | 0 |

**Sei combinazioni su sei recuperano zero righe**, compreso ogni writer
accoppiato al parser che vive nel suo stesso crate. Eppure le righe prodotte
hanno l'aspetto del `.pat` IDA canonico:

```
404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00 0000 0040 exact_fn
404142........4748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00 0000 0040 wildcard_fn
```

Un `.pat` e' un formato di interscambio testuale: esiste per essere passato a un
altro strumento, o restituito a questo. Un round-trip che torna vuoto significa
che **i writer `.pat` sono di fatto write-only**.

**Due cose che ho corretto nello strumento prima di pubblicare il numero**, e che
valgono piu' del numero stesso:
1. la prima versione contava come "righe scritte" anche gli header di commento
   (`;` e `#`), quindi avrebbe attribuito ai parser un fallimento piu' grande di
   quello reale;
2. ho misurato due volte, con e senza commenti, per non confondere "non gestisce
   l'header" con "non sa leggere la riga". Falliscono entrambe: `InvalidHex` sul
   file intero, `InvalidLine` sulle sole righe dati. Senza questa separazione la
   diagnosi sarebbe stata sbagliata pur con il numero giusto.

**Questa iterazione fissa il difetto, non lo risolve.** 3 test in
`tests/pat_round_trip_is_broken.rs`, incluso un guard che verifica che il writer
produca davvero righe ben formate — altrimenti "nessun parser le legge" sarebbe
vero per un motivo banale e non direbbe niente sui parser.
Il test `no_parser_reads_what_our_own_writer_produces` e' scritto per **fallire
quando T4 avra' successo**, con il messaggio che lo spiega.

T4 ha ora un criterio di successo misurabile (0/6 -> 3 righe per cella) e una
decisione da prendere prima di iniziare: quale dialetto e' canonico.

**Test: 2141 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 49 (T4 primo passo: il round-trip `.pat` si chiude)

L'iterazione 48 aveva misurato la matrice writer x parser a **0 su 6** e lasciato
a T4 una decisione: quale dialetto e' canonico. L'ho decisa **misurando invece
che scegliendo**, con `examples/why_pat_parsers_reject.rs`:

- `apply::pat_parser` pretende un `:` iniziale e `crc_len` **decimale** — non e'
  una variante del `.pat` IDA, e' un formato diverso che porta lo stesso nome;
- `pat_parser_v2` pretende un prefisso noto su ogni nome piu' un campo `delta`
  (`BadModuleRef: unknown prefix`);
- `SimpleFlirtDatabase::parse_pat_text` non accetta nessuno dei due **e scarta
  gli errori in silenzio** — ed e' per questo che "zero pattern recuperati"
  poteva sembrare un parsing riuscito.

Nessuno accetta il formato documentato, che e' pero' cio' che **entrambi i
writer emettono** e l'unico che un tool esterno produce. Quindi il canonico non
era una preferenza: era l'unica scelta compatibile sia con noi sia con il mondo.

`rustre-flirt/src/pat_canonical.rs` lo implementa. Misurato end-to-end (writer
reale -> parser canonico): **3 pattern su 3**, con nomi corretti, wildcard agli
offset **3,4,5,6** (non spostati), `crc_length` 8, `crc16` 0xBEEF e
`pattern_length` 64 intatti. Prima: 0.

Due proprieta' che ho pinnato perche' sono i modi in cui questo formato fallisce
in silenzio: il terminatore `---` deve fermare la lettura (una riga dopo di esso
non deve entrare), e le righe malformate devono essere **riportate**, non
scartate. `parse_text` restituisce `(pattern, errori)` proprio per non ripetere
il difetto di `parse_pat_text`.

**Deliberatamente additivo.** I tre parser dialettali non sono stati toccati: i
loro test restano verdi, e resta verde anche `pat_round_trip_is_broken.rs`, che
continua a registrare che *quei* parser non leggono il nostro output. Sara' quel
test a dover fallire quando i chiamanti verranno spostati — non prima.

**Resta da fare** (T4 secondo passo): spostare i chiamanti su `pat_canonical` e
ridurre i tre a re-export. Serve decidere quali muovere per primi.

**Test: 2147 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.
**Neutralita' misurata:** round-trip di T14 identico riga per riga.

## 2026-07-30 — Iterazione 50 (T4: e una correzione a cio' che ho pubblicato due iterazioni fa)

### La correzione, prima di tutto

L'iterazione 48 ha pubblicato: **"i writer `.pat` sono di fatto write-only"**.
E' falso, e la differenza cambia le conclusioni di chi legge.

Cercando i chiamanti da spostare per T4, ho misurato che esiste un **quarto**
parser `.pat`, privato: `parse_pat_line` in `flirt-apply/src/lib.rs`, raggiunto
da `load_pat_file` e `load_auto` — cioe' **il percorso che un chiamante reale
prende davvero**. La matrice dell'iterazione 48 copriva i tre parser *pubblici*
e lo aveva mancato.

Misurato (`examples/pat_production_path.rs`): writer reale -> `load_pat_file` ->
**3 firme su 3**, wildcard conservati agli offset 3,4,5,6, `crc_len` 8 e `crc`
0xBEEF intatti. I due lettori (produzione e canonico) concordano sullo stesso
file.

Cio' che resta vero dell'iterazione 48 e' piu' ristretto: tre parser pubblici con
dialetti mutuamente incompatibili, nessuno dei quali legge il formato
documentato, e uno (`parse_pat_text`) che **scarta gli errori in silenzio**. E'
duplicazione e un'API pubblica fuorviante, **non** perdita di dati sul percorso
che spedisce. La differenza conta perche' cambia l'urgenza: non e' un incendio.

Corretto in tre posti: il doc del test `pat_round_trip_is_broken.rs` (compreso il
titolo, che affermava la cosa sbagliata), la voce T4b in TODO.md, e la memoria.

### Il lavoro dell'iterazione

5 test in `tests/pat_production_path_reads_our_output.rs` che fissano il percorso
di produzione — cosi' una futura consolidazione non puo' rompere in silenzio
l'unico lettore che oggi funziona. Incluso un test che verifica che il lettore di
produzione e `pat_canonical` **concordino** sullo stesso file: se divergessero,
consolidare su uno dei due cambierebbe il comportamento senza che si veda.

T4 resta `[~]`: il parser canonico esiste (iterazione 49) e il percorso di
produzione e' fissato; manca ridurre i tre pubblici a re-export, che ora si sa
essere un lavoro di pulizia dell'API, non un salvataggio.

**Test: 2152 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 51 (T4: non ci sono chiamanti da spostare)

Il passo che restava a T4 era "spostare i chiamanti su `pat_canonical`". Misurato:
**non ce ne sono**. I tre parser dialettali pubblici hanno **zero riferimenti in
codice di produzione** nei quattro crate — vivono solo nei propri test. Il lettore
che spedisce e' il quarto, privato, raggiunto da `load_pat_file` (la correzione
dell'iterazione 50).

**Verificato con un test che enumera, non con un grep**, perche' su questa stessa
domanda ho gia' sbagliato due volte: l'iterazione 50 ha scoperto un parser che la
matrice sui simboli pubblici non vedeva, e la caccia al CRC aveva dichiarato
"nessun duplicato" cercando solo i polinomi riflessi. Il test:
- cammina `src/`, `tests/`, `examples/` dei 4 crate e classifica ogni riferimento;
- **esclude i `#[cfg(test)]` inline** dei file di produzione (contarli come
  produzione avrebbe sottostimato quanto sono morti — direzione sicura, ma falsa);
- porta un **controllo positivo** su `crc16_flirt`, che deve risultare usato: se
  fallisse, sarebbe lo scanner a essere rotto, non i parser a essere morti.

**Limite dichiarato**: lo scan vede solo dentro il workspace. Quei parser sono
`pub`, quindi un chiamante esterno non e' escluso. La conclusione onesta e'
"sicuro consolidare *dentro* il workspace", non "sicuro cancellare".

**Ne segue una decisione, non un'azione.** Farli delegare a `pat_canonical`
cambia il formato accettato da API pubbliche e fa fallire i loro test dialettali —
test che codificano formati che nessuno usa e che nessun tool esterno produce, ma
pur sempre un breaking change. Stessa classe di T38, quindi non la prendo da solo.

**Test: 2155 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 52 (T5: correttezza prima della velocita', e una previsione sbagliata)

T5 dice di scegliere il matcher vincente **con un benchmark**. Ma un benchmark
ordina per velocita', e la velocita' conta solo fra implementazioni che danno la
**stessa risposta**. Quindi ho misurato prima l'accordo, sul primitivo che tutti
esprimono: dato un pattern con wildcard e un buffer, a quali offset combacia?

**Una previsione mia, sbagliata e informativa.** Avevo scritto il test
aspettandomi che lo scanner di produzione **non** trovasse nulla, dato che il
container `.sig` tronca il pattern al primo wildcard. Lo trova, a offset 8:
`([8], [8])`. Il motivo pero' non e' lo stesso — `PatternMatcher` onora la
maschera su tutti e 16 i byte, lo scanner combacia sul **prefisso di 3 byte**
superstite. Stesso offset, evidenza completamente diversa.

Quindi "i matcher concordano" era vero e inutile su quell'input. Il test che
separa davvero i due: un buffer che contiene solo il prefisso di 3 byte, seguito
da byte che **contraddicono** il resto del pattern.

- `PatternMatcher`, che ha tutti i 16 byte: **nessun match** (corretto).
- Scanner di produzione, che ha una chiave di 3 byte: **match a offset 8**.

**E' un falso positivo riprodotto in cinque righe**, ed e' esattamente la forma
dei 5 falsi positivi misurati cross-binario su un binario Go che non puo'
contenere quelle funzioni. Prima era un'osservazione statistica su 522 firme;
ora e' un caso minimo e deterministico.

**Conseguenza per T5, che cambia il piano**: il vincitore non puo' essere scelto
con un benchmark finche' il container scarta i wildcard, perche' si
misurerebbe la velocita' di due cose che rispondono a domande diverse.

5 test in `tests/matchers_agree_on_where_a_pattern_matches.rs`, incluso il
controllo su pattern esatto (per non attribuire ai wildcard una divergenza
generale) e uno che verifica che nessuno dei due inventi match.

**Test: 2160 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 53 (la causa radice: il container ora trasporta i wildcard)

Le iterazioni 45-52 avevano fatto convergere l'evidenza su una sola causa:
`SigWriter::build` troncava il pattern al primo wildcard
(`take_while(PatternByte::Exact)`), quindi una firma di 16 byte raggiungeva lo
scanner come chiave di 3. Il commento nel codice spiegava il ragionamento — IDA
usa una bitmask separata, e emettere un wildcard come `0x00` in-band sarebbe
indistinguibile da uno `0x00` vero — quindi il ripiego era scartare. Difendibile,
e costava tutto.

**Correzione: il leaf ora porta una coda mascherata.** Il byte di controllo del
nodo distingueva interno (0) da leaf (non-zero); ora `0x02` significa "leaf con
coda". Dopo il byte di controllo viaggiano `tail_len:u8`, i byte della coda e la
sua maschera (`0xFF` concreto, `0x00` wildcard). Il trie resta indicizzato su
byte concreti — un wildcard non puo' stare in una chiave — ma tutto cio' che
segue la chiave viaggia con la maschera. **I file scritti prima (ctrl `0x01`)
restano leggibili**: il loader li tratta come oggi.

### Misure, prima e dopo

Auto-riconoscimento (`libz.a`, 132 pattern, 26 con wildcard):

| sottoinsieme | prima | dopo |
|---|---|---|
| tutti | 86 (65.2%) | **97 (73.5%)** |
| con wildcard | 3 (11.5%) | **14 (53.8%)** |
| senza wildcard | 83 (78.3%) | 83 (78.3%) — invariato, non avevano coda |

Cross-binario (`libmingwex.a`, 522 firme, target mingw + controllo Go):

| | prima | dopo |
|---|---|---|
| falsi positivi sul binario Go | 5 | **0** |
| nomi sul target | 4 | 2 |

Il calo sul target da 4 a 2 e' atteso e **corretto**: 3 dei 4 venivano dai
pattern troncati, cioe' erano quasi certamente falsi anch'essi. Ora restano 1 dal
gruppo integro e 1 dai wildcard, e i falsi positivi sono zero **a ogni soglia,
compresa nessuna**.

Database rust-stdlib su **6 binari estranei**, falsi positivi a soglia 0:
**5071 → 0**.

### Cosa ne segue per una decisione aperta

**La soglia 16 non serve piu' come difesa.** Era un filtro che compensava firme
arrivate corte; con i pattern interi non c'e' piu' nulla da filtrare — 0 falsi
positivi gia' senza soglia, su entrambi i corpora. Resta utile come cintura di
sicurezza, non come necessita'. La decisione dell'utente su questo punto e'
quindi molto meno urgente di ieri, e la motivo diversamente.

### Cinque test hanno dovuto cambiare, ed e' il punto

Cinque test fallivano dopo la correzione, **tutti** perche' fissavano il difetto:
il troncamento a 3 byte, il falso positivo in cinque righe, i 5 falsi positivi
cross-binario, i 5071 su rust-stdlib. Erano stati scritti per fallire esattamente
in questo momento, e i loro messaggi lo dicevano. Riscritti in positivo, con il
valore precedente citato nel doc, cosi' una regressione si riconosce dal numero e
non solo dal rosso.

**Test: 2159 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 54 (T3c chiuso davvero: il CRC ora non costa piu' nulla)

Dopo l'iterazione 53 l'auto-riconoscimento era 73.5% con CRC contro 97.0%
azzerandolo: il campo continuava a **rifiutare** match invece di confermarli.
Restava il difetto originale di T3c, ora risolto alla radice.

**Causa esatta.** `crc_over_stable_region` **saltava** gli offset mascherati
ovunque nella finestra e raccoglieva `crc_length` superstiti, quindi hashava byte
**non contigui**; lo scanner hasha `crc_len` byte **contigui** dopo il pattern.
Le due definizioni coincidono solo quando nella finestra non c'e' nulla di
mascherato — per questo era invisibile sulle funzioni semplici e fatale su quelle
rilocate.

**Correzione**: la finestra si ferma al **primo** byte mascherato. Cosi'
`crc_len` significa la stessa cosa sui due lati — "tanti byte contigui dopo il
pattern" — e generatore e scanner concordano per costruzione invece che per caso.
Una funzione il cui byte successivo e' rilocato ottiene `crc_len == 0`, cioe'
nessun CRC: onesto, invece di memorizzarne uno irriproducibile.

### Auto-riconoscimento su `libz.a`, le tre tappe

| | con CRC | CRC azzerato |
|---|---|---|
| iter. 38 (partenza) | 65.2% | 97.0% |
| iter. 53 (coda mascherata) | 73.5% | 97.0% |
| **iter. 54 (finestra contigua)** | **97.0%** | 97.0% |

Le due colonne ora coincidono: **il campo non costa piu' un solo match**. Sul
sottoinsieme senza wildcard: **100.0%** (106 su 106). Sui wildcard: 84.6%, cioe'
esattamente la baseline senza CRC — il residuo non e' piu' attribuibile al CRC.

Cross-binario invariato e sano: 2 nomi sul target, **0 falsi positivi** sul
binario Go, a ogni soglia.

### Un test ha dovuto cambiare, e vale la pena dire perche'

`test_generate_from_ranges_crc_skips_masked` fissava la regola vecchia fin dal
nome. Il suo intento — "due funzioni che differiscono solo in un dword rilocato
danno lo stesso CRC" — resta valido, e ora e' soddisfatto **piu'** fortemente:
la finestra esclude del tutto la regione rilocata. Riscritto in due casi:
rilocazione subito dopo il pattern (`crc_len == 0`, nessun CRC) e due byte
stabili prima della rilocazione (`crc_len == 2`, CRC ricalcolabile dallo scanner).

2 test nuovi in `tests/crc_no_longer_costs_matches.rs`, che fissano la proprieta'
invece del numero: portare un CRC non deve perdere **nessun** match rispetto a
non portarlo.

**Test: 2161 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 55 (il recall non era basso: era il denominatore sbagliato)

### La correzione

Le iterazioni 46-47 hanno pubblicato: **"il recall reale e' circa 1 su 522"**.
L'aritmetica era giusta, la conclusione no. **522 e' il denominatore sbagliato.**

Un linker statico include solo i membri d'archivio che servono al programma,
quindi quasi nulla di `libmingwex` sta dentro `sample1_c.exe` — e una firma per
una funzione mai collegata non e' trovabile da nessun matcher.

Misurato con un oracolo che non richiede simboli (`examples/recall_ceiling.rs`):
per ogni pattern, cercare nel target la sua sequenza iniziale di byte concreti.

| prefisso minimo | firme | byte d'ingresso presenti nel target |
|---|---|---|
| >= 4 byte | 513 | **3** |
| >= 8 byte | 495 | **1** |
| >= 12 byte | 469 | 1 |
| >= 16 byte | 445 | 1 |

Lo scanner ne trova **2**. Il tetto e' circa 3, non 522: **il matcher e' vicino
al tetto, non lontano da esso**. "1 su 522" descriveva il comportamento del
linker, non il nostro.

Riportato a piu' lunghezze di prefisso di proposito: una sequenza di 4 byte
ricorre per caso, quindi un numero solo avrebbe sovra-affermato esattamente come
facevano i falsi positivi da prefisso corto.

**Limite dichiarato**: la presenza dei byte e' necessaria, non sufficiente — una
sequenza puo' capitare dentro una funzione non correlata. Quindi il tetto e' un
limite **superiore** a cio' che e' trovabile, che e' la direzione sicura per
l'affermazione che si sta facendo.

### Perche' ci sono cascato

L'auto-riconoscimento (97.0%) e il cross-binario (2 nomi) sembravano in
contraddizione, e ho attribuito la differenza al matcher senza chiedermi se le
funzioni ci fossero. Il numero brutto sembrava piu' onesto di quello bello, e per
questo non l'ho messo in discussione — ma un numero pessimista non e' piu'
verificato di uno ottimista.

3 test in `tests/recall_is_bounded_by_the_target.rs`, incluso uno che fallisce se
il matcher si allontana dal tetto: quella volta il difetto sarebbe davvero nostro.

**Test: 2164 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 56 (T28: quale archivio conviene, e un limite del mio stesso oracolo)

T28 chiede di generare i `.sig` per il runtime del corpus. Quale? L'iterazione 55
aveva mostrato che `libmingwex` e' quasi assente dal binario. Invece di scegliere
a intuito ho usato l'oracolo del tetto come **indagine**, su piu' archivi:

| archivio | firme | trovabili (>=8B) | trovate |
|---|---|---|---|
| `libmingw32` | 43 | 24 | **24** |
| `libmsvcrt` | 364 | 7 | **7** |
| `libmingwex` | 522 | 1 | 2 |
| `libucrt` | 68 | 0 | 2 |
| `libstdc++` (vs C++) | 5427 | 187 | **5** |

**Il runtime davvero collegato nei binari C del corpus e' `libmingw32`**, piu' una
piccola parte di msvcrt — non `libmingwex`. Ed e' un risultato incoraggiante: su
entrambi il matcher e' **esattamente al tetto** (24 su 24, 7 su 7).

### Il limite del mio oracolo, trovato misurando

`libstdc++` non torna: 187 trovabili, 5 trovate. Prima di chiamarlo difetto ho
verificato l'ipotesi piu' ovvia — la scala del database — riducendolo alle sole
187 firme trovabili. Ne trova **3**. Quindi non e' la scala: sono i pattern.

La lettura coerente con i dati e' che in C++ i **prologhi siano condivisi**: lo
stesso avvio di 16 byte appartiene a molte funzioni distinte (istanze di
template, thunk, wrapper). La presenza di quei byte non dice che *quella*
funzione ci sia. Quindi **il tetto e' un limite superiore lasco su C++ e stretto
su C**, e "187 trovabili" non va letto come "182 mancate".

E' un limite dello strumento che avevo introdotto ieri, trovato con una misura
invece che con un'assunzione. L'ho scritto nel doc del test, e l'assertion usa il
binario C proprio perche' li' il tetto e' abbastanza stretto da voler dire
qualcosa.

**Test: 2164 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 57 (T28: catena end-to-end misurata; il moltiplicatore Level 7 e' zero, e ora si sa perche')

### Un difetto trovato mentre generavo le firme

`harvest_archives` filtrava su `.rlib`/`.lib` e **non vedeva i `.a`** — cioe'
l'intero runtime GNU/mingw (`libmingw32.a`, `libmsvcrt.a`, `libgcc.a`), che
l'iterazione 56 aveva appena identificato come l'unico che il corpus collega
davvero. Aggiunta l'estensione. Generate **255 firme** da libmingw32+libmsvcrt
(407 grezze, 26 duplicati esatti scartati, 44 chiavi ambigue, 211 discriminanti).

### La misura che conta: effetto sul decompiler

Decompilato `sample1_c.exe` con e senza `RUSTRE_SIGDB_DIR`:
**i 43 file `.c` emessi sono byte-identici.** Differiscono solo `elapsed_ms`
(26 -> 264) e `out_dir` in `summary.json`.

Traccia di debug:
```
[flirt] scanner: 1 pack + 3 database .sig = 108634 firme
[flirt] match grezzi 65, dopo resolve 65
[flirt→typerecov] considerate 28, pubblicate 0, senza prototipo 28
```

Quindi la scansione **funziona** (65 match) e il ponte pubblica **zero**.

### Perche', esattamente — e perche' non e' il compito di data-entry che sembrava

Divario misurato (`examples/prototype_gap_for_matched_names.rs`): dei **29** nomi
che combaciano, **4 hanno un prototipo** (`__acrt_iob_func`,
`__mingw_raise_matherr`, `_configthreadlocale`, `_matherr`) e **25 no**.

I 25 sono impalcatura interna di mingw, non API pubbliche: `__main`,
`__do_global_ctors`, `__do_global_dtors`, `_pei386_runtime_relocator`,
`__mingw_TLScallback`, `_FindPESectionByName`, `___w64_mingwthr_add_key_dtor`,
`__dyn_tls_init`, `_gnu_exception_handler`, `fpreset`…

**Questo riscrive il compito.** "Colmare il divario dei prototipi" sembrava
estrazione dagli header; per questi nomi gli header **non li dichiarano**, perche'
sono interni. Ottenerne le firme richiede reverse engineering, non estrazione. E'
un tetto sul valore che Level 7 puo' dare su questo corpus, non una casella da
spuntare.

### Una discrepanza che lascio aperta invece di spiegarla

4 nomi combacianti **hanno** un prototipo, eppure il ponte riporta
"considerate 28, pubblicate 0, senza prototipo 28". O quei 4 non compaiono fra i
call site considerati, o la normalizzazione dei nomi differisce fra le due parti.
Non l'ho misurato, quindi non lo affermo: e' il primo controllo della prossima
iterazione.

**Test: 2164 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 58 (la discrepanza spiegata: il ponte funziona, e la mia misura di ieri era contaminata)

PROGRESS indicava questa come prima verifica: 4 nomi combacianti hanno un
prototipo, eppure la traccia diceva `pubblicate 0`. Verificata, e ha prodotto due
correzioni a quanto avevo pubblicato ieri.

### 1. La misura dell'iterazione 57 era contaminata

`RUSTRE_SIGDB_DIR` puntava a una cartella che conteneva gia' `all.sig` e
`pubonly.sig` di una sessione precedente. Il decompiler caricava quindi **108 634
firme** (in prevalenza rust-stdlib), mentre la scansione con cui la confrontavo
ne usava 255. **Stavo confrontando due run diversi e leggendo la differenza come
un risultato.** Rifatto con una cartella isolata: 263 firme, **26 match grezzi**,
e comunque **0 pubblicate**.

### 2. Il ponte non e' il collo di bottiglia — ieri l'avevo attribuito a lui

Dando al ponte le identificazioni prodotte dal nostro scanner:

| | considerate | pubblicate |
|---|---|---|
| tutte | 33 | **4** |
| dopo il filtro ambiguita' | 26 | **4** |

I quattro sono `__acrt_iob_func`, `__mingw_raise_matherr`, `_configthreadlocale`,
`_matherr`. E non e' il filtro ambiguita' a rimuoverli: scarta `__cxa_atexit`,
`__mingw_GetSectionForAddress` e `_setargv`, nessuno dei quali ha un prototipo.

**Quindi il ponte pubblica quel che puo'.** Cio' che non contiene quei nomi e' la
lista di identificazioni che il decompiler produce — e quella nasce a monte, nel
suo scanning, che percorre le sezioni mappate a indirizzi virtuali mentre questo
test scansiona il file a offset 0. E' un altro crate e un'altra misura: lo
scrivo come osservazione, non come diagnosi, perche' non l'ho misurato.

**Cosa resta valido dell'iterazione 57**: i 25 nomi senza prototipo sono davvero
impalcatura interna mingw, e per quelli il divario non si colma estraendo dagli
header. Cio' che **non** e' valido e' averne concluso che il ponte fosse il
limite: con 4 su 33 pubblicate, non lo e'.

2 test in `tests/bridge_publishes_known_prototypes.rs`, di cui uno fallisce se il
filtro ambiguita' iniziasse a scartare i nomi utili.

**Test: 2166 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 59 (i nostri match sono legittimi: cadono tutti in `.text`)

L'iterazione 58 aveva lasciato una domanda: il ponte pubblica 4 delle nostre 33
identificazioni, il decompiler 0 delle sue 26. Prima di concludere qualcosa sul
decompiler andava esclusa la spiegazione piu' economica — che i **nostri** match
fossero spuri. Noi scansioniamo il file grezzo da offset 0: una sequenza di byte
puo' capitare negli header, nei dati, nelle rilocazioni o nella tabella import
senza essere quella funzione. Se fosse cosi', il decompiler avrebbe ragione a
ignorarli.

Misurato contro la tabella delle sezioni PE di `sample1_c.exe`:

| sezione | match |
|---|---|
| `.text` | **33** |
| ogni altra | 0 |

E i quattro nomi che portano un prototipo — `_matherr`, `__mingw_raise_matherr`,
`_configthreadlocale`, `__acrt_iob_func` — cadono **tutti in codice eseguibile**.

**Quindi le identificazioni sono legittime.** Cio' che resta e' che la lista del
decompiler non le contiene. Quella lista nasce in un altro crate, quindi lo
registro come fatto misurato sul nostro lato e non come diagnosi sul loro.

Il quadro del collo di bottiglia Level 7, ora sostenuto da misure e non da
ipotesi:
- lo scanner trova 33 identificazioni, tutte in `.text`;
- il ponte ne pubblica 4, e il filtro ambiguita' non e' cio' che rimuove le
  altre;
- 25 dei nomi combacianti sono impalcatura interna mingw senza prototipi
  pubblicati — per quelli il divario non si colma estraendo dagli header;
- il decompiler produce una lista diversa, che non contiene i 4 pubblicabili.

3 test in `tests/matches_land_in_executable_code.rs`, incluso il guard di
vacuita' (se il parsing del PE si rompe, il test lo dice invece di passare).

**Test: 2169 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 60 (T5: il benchmark, e un difetto del benchmark stesso)

T5 chiedeva di scegliere il matcher vincente con un benchmark. Prima di misurare
ho verificato chi sia vivo: **nessuno dei quattro candidati** (`signature_matcher`,
`signature_matcher_new`, `sig_matcher`, `flirt_matcher_v2`) e' referenziato da
codice di produzione. Cio' che spedisce e' `FlirtScanner::scan_fast`.

Quindi "quale dei quattro vince" ordinerebbe quattro cose che nessuno chiama. La
domanda utile e' un'altra: **qualcuno batte quello che spedisce?**

Misurato su un buffer di 2 MB con un'occorrenza piantata per firma:

| firme | lineare | `scan_fast` | rapporto |
|---|---|---|---|
| 16 | 21.9 ms | 0.49 ms | **44x** |
| 128 | 174 ms | 0.76 ms | **229x** |
| 1024 | 1.46 s | 6.95 ms | **209x** |

Conteggi degli hit **identici** a ogni taglia. Il divario cresce col database,
come atteso: il lineare e' O(pattern x byte), l'indice ~O(byte).
**Nessun candidato batte quello in produzione.** T5 si riduce quindi alla stessa
decisione di API pubblica di T38, non a una scelta tecnica.

### Due difetti del benchmark, trovati e corretti prima di pubblicare i numeri

1. **Zero hit.** La prima versione non piantava le occorrenze, quindi misurava
   solo il percorso di scarto — il reject veloce — e non diceva nulla sul costo
   di verificare un hit, che e' dove vivono CRC e coda.
2. **Il generatore fabbricava la divergenza che sembrava misurare.** Il seed era
   `i as u8`, che satura a 256: 1024 pattern richiesti erano 256 distinti
   ripetuti quattro volte, e il lineare riportava 4128 hit contro 1024. Con due
   byte di seed i conteggi coincidono.

Il secondo e' il piu' istruttivo: stavo per pubblicare "i due matcher trovano
numeri diversi" come risultato, quando era un artefatto dei miei input. Gli input
di un benchmark vanno guardati con lo stesso sospetto del codice sotto test — c'e'
ora un test che fallisce se i pattern generati tornano a ripetersi.

**Test: 2171 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 61 (T6 e T7: una premessa sbagliata e una strada chiusa)

### T6: stessa parete di T4 e T5

`batch_applicator`, `batch_applier`, `bulk_applier`, `flirt_auto_apply`: **zero
riferimenti di produzione**. Come per i parser e i matcher, "collassarli" non e'
una scelta tecnica ma la decisione di API pubblica gia' in coda con T38.

### T7: la premessa del task e' sbagliata

T7 li chiama "i propagatori di nomi", da fondere in uno. **Non sono lo stesso
concetto**: `name_propagator` percorre il call graph propagando nomi fra
chiamante e chiamato; `rename_propagator` porta firme di funzione con tipi C e le
applica. Ed entrambi sono **vivi** (4 e 3 riferimenti). Fonderli unirebbe due
lavori diversi — lo stesso errore, gia' registrato all'iterazione 41, di trattare
ogni nome duplicato come concetto duplicato.

### La ricaduta su Level 7, che era la parte promettente

`rename_propagator::builtin_signatures()` restituisce prototipi, e il ponte non
lo consulta: sembrava una seconda fonte capace di colmare il divario misurato
(25 nomi combacianti senza prototipo). Misurato:

| | conteggio |
|---|---|
| prototipi noti al ponte | 227 |
| firme builtin del propagatore | 88 |
| in comune | **88** |
| solo nel propagatore | **0** |
| dei 25 nomi mancanti, coperti | **0** |

Le 88 sono un **sottoinsieme stretto**. Non c'e' nessuna fonte inesplorata, e
collegarla non recupererebbe niente. E' un risultato negativo, ma misurato: la
strada e' chiusa con un numero invece di restare un'intuizione da riesplorare fra
dieci iterazioni.

3 test in `tests/prototype_sources_do_not_diverge.rs`. Uno confronta l'**arieta'**
delle firme condivise e non solo i nomi: due record per la stessa funzione che
non concordano sul numero di parametri sarebbero la stessa classe di difetto dei
tipi duplicati misurata prima.

**Test: 2174 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 62 (T8: quattro decisioni diventano una, e lo scanner mentiva)

T4, T5, T6 e T38 finivano tutti contro la stessa parete: i moduli sono `pub`,
quindi toglierli e' un breaking change e decide il maintainer. Quattro richieste,
una domanda. Misurata tutta insieme:

| | conteggio |
|---|---|
| moduli pubblici nei 4 crate | 70 |
| usati da codice di produzione | 23 |
| non usati dalla produzione | 47 |
| …di cui usati da test/example | **17** |
| **senza alcun uso nel workspace** | **30** |

I 17 non sono un dettaglio: test d'integrazione ed example sono **crate
separati**, quindi raggiungono solo item `pub`. Renderli `pub(crate)` romperebbe
i test — e' una decisione diversa dal cancellarli. **I 30 sono la lista
azionabile.**

### Lo scanner mentiva, e nella direzione pericolosa

La prima versione riportava **52 moduli morti**, fra cui `sig_file_loader`
(referenziato quattro volte in `lib.rs`) e `typerecov_bridge` (chiamato dal
decompiler). Due difetti, entrambi che facevano sembrare morto cio' che e' vivo:

1. tagliava ogni file al primo `#[cfg(test)]`, buttando via tutto il codice di
   produzione che seguiva un modulo di test inline;
2. cercava i riferimenti solo nei 4 crate, mentre i consumatori stanno altrove.

Stavo per pubblicare "52 moduli morti" come risultato. Ho aggiunto un **controllo
positivo** — due moduli certamente usati che non devono comparire nella lista —
ed e' quello che ora impedisce a uno scanner muto di sembrare una scoperta
clamorosa. E ho invertito il bias: il codice di test inline **conta** come
riferimento, cosi' un modulo finisce nella lista solo se non lo nomina nessuno.
Sovrastimare tiene fuori un modulo vivo; sottostimare ce lo mette dentro, ed e'
l'errore che conta.

**Test: 2176 passati, 0 falliti, 0 target FAILED** sui 4 crate, release,
`--no-fail-fast`, entrambe le colonne. Build release pulita.

## 2026-07-30 — Iterazione 63 (T24: il numero era sbagliato, e il difetto non era fra quelli contati)

T24 diceva "55 `unwrap/expect/panic` su 54 `pub fn`". Due correzioni.

**Il conteggio.** In codice di produzione sono **9**, non 55: i 55 includono i
test, lo stesso sovra-conteggio gia' pagato con i "416 unwrap" che erano 50. E
contarli bene non e' banale: tagliando al **primo** `#[cfg(test)]` ne risultano
**6**, perche' si perde tutto il codice di produzione che segue un modulo di test
inline — e' la stessa trappola dell'iterazione 62, ripetuta un'iterazione dopo
averla registrata. Contati per profondita' di graffe: 9.

**Il difetto vero non era fra quelli contati.** Era un `assert!`, che nessuna
ricerca di `unwrap|expect|panic` trova:

```rust
// Guard against OOM from an adversarially large var_count.
const MAX_NODES: u32 = 1 << 24;
assert!(n <= MAX_NODES, …);
```

Il commento dichiara che l'input e' ostile, e poi lo protegge **andando in
panic**. Misurato prima della correzione: `TypeUnifier::new(16_777_217)` abortiva
il processo. `var_count` deriva dal binario analizzato, quindi un file costruito
ad arte abbatteva qualunque strumento costruito sul crate: **il panic era il
denial of service che la guardia doveva impedire**.

**Correzione additiva**, per non rompere i chiamanti che il conteggio lo
controllano: `TypeUnifier::MAX_VARIABLES` esposta, `TypeUnifier::try_new` e
l'entry point pubblico `unify_types` restituiscono
`UnifyError::TooManyVariables`; `new` resta e ora documenta di panicare.

5 test, incluso il caso **esattamente al tetto**: un limite che rifiuta il
proprio valore massimo perderebbe in silenzio l'input legittimo piu' grande, ed e'
un errore altrettanto reale del non avere limite.

**Test: 2181 passati, 0 falliti, 0 target FAILED** — misurati per crate
(527 + 559 + 317 + 778), ciascuno con exit 0, perche' la run unica andava in
timeout a 590 s e un totale da una run troncata non e' un totale. Build release
pulita.

## 2026-07-30 — Iterazione 64 (T24: la correzione di ieri copriva meta' del problema)

Cercando la stessa classe di difetto negli altri crate — guardie a forma di
panic, che nessun inventario di `unwrap|expect` trova — ne sono emerse **9** in
produzione. Due cluster, e uno era ancora aperto proprio dove avevo appena
corretto.

**Ieri ho corretto il costruttore, non il percorso.** `TypeUnifier::try_new`
rifiuta un `var_count` ostile, ma i **vincoli portano i propri id di TypeVar**,
nascono dal binario analizzato, e `solve` li passava dritti all'union-find.
Misurato: un solo vincolo con `TypeVar(16_777_215)` abortiva il processo.

L'id merita attenzione: **16 777 215 e' sotto il tetto** (2^24). Non era un
valore fuori range — lo faceva cadere la guardia anti-amplificazione
(`MAX_GROWTH_PER_CALL`), anch'essa scritta come `assert!`. Controllare
`var_count` da solo non l'avrebbe trovato mai: e' per questo che la sonda e'
passata dall'**entry point pubblico** invece che dal costruttore.

Ora `solve` valida ogni id dei vincoli prima di toccare l'union-find e pre-alloca
a passi limitati, cosi' la guardia per chiamata resta un'invariante interna
invece di un panic raggiungibile. Dopo:

```
TypeVar(16777215) -> ok
TypeVar(16777216) -> Err(too many type variables: … maximum is 16777216)
TypeVar(4294967295) -> Err(…)
```

4 test, incluso uno per **ogni forma** di vincolo: validare solo `Equal`
lascerebbe le altre come via d'ingresso.

**Una regressione mia, colta dalla suite e riparata prima di procedere.** La
prima versione ragionava in *id* invece che in *lunghezza*: con
`TypeUnifier::new(0).solve(&[])` allocava comunque un nodo e `class_count`
passava da 0 a 1. Un test esistente (`unifier_solve_empty`) l'ha fermata.

**Test: 2185 passati, 0 falliti, 0 target FAILED** — misurati per crate
(527 + 559 + 778 + 321), ciascuno con exit 0. Build release pulita.

## 2026-07-30 — Iterazione 65 (T24: terza istanza della stessa forma, e un difetto in piu')

Restavano due guardie non verificate dallo sweep dell'iterazione 64, in
`StructRecoveryEngine`. Il doc di `record_all` diceva testualmente:

> Panics if the total number of recorded accesses would exceed `MAX_ACCESSES`
> (8 M), **preventing denial-of-service via memory exhaustion when analysing
> adversarially-crafted binaries**.

Nomina la minaccia e le risponde andando in panic — la terza volta che questa
forma compare in due iterazioni. Gli accessi ai campi derivano dal file
analizzato, quindi il loro numero e' influenzato dall'attaccante.

Aggiunti `StructRecoveryEngine::MAX_ACCESSES` (pubblica), `try_record` e
`try_record_all`, che restituiscono `StructRecoveryError::TooManyAccesses`. Le
versioni che panicano restano, e ora dichiarano di farlo.

**Un secondo difetto, rimosso dalla riscrittura.** `record_all` asseriva
**dentro** il ciclo, dopo aver gia' inserito parte dell'input: chi catturava il
panic restava con un motore mezzo pieno e nessun modo di sapere quanto fosse
entrato. `try_record_all` restituisce il conteggio, cosi' una corsa troncata si
distingue da una completa.

**Cio' che non ho testato, e perche' lo dico.** Il tetto vero (8 M accessi) non e'
esercitato: raggiungerlo richiede circa un gigabyte di `FieldAccess`, e un test
del genere misurerebbe l'allocatore. I 4 test verificano la **forma** del
fallimento — che e' cio' che e' cambiato — piu' la costante e il contenuto
dell'errore. Un test che allocasse davvero direbbe meno, non di piu'.

**Test: 2189 passati, 0 falliti, 0 target FAILED** — per crate
(527 + 559 + 778 + 325), ciascuno con exit 0. Build release pulita.

## 2026-07-30 — Iterazione 66 (T24 chiuso: dalla caccia ai singoli casi a un gate sulla classe)

Tre panic raggiungibili corretti in tre iterazioni, tutti della stessa forma.
Continuare a cercarli uno per uno non scala: serve un conteggio della classe.

Misurata la superficie di panic nel codice di produzione dei 4 crate (blocchi
`#[cfg(test)]` esclusi per profondita' di graffe):

| crate | costrutti |
|---|---|
| `rustre-flirt` | 4 |
| `rustre-flirt-gen` | 9 |
| `rustre-flirt-apply` | 32 |
| `rustre-analysis-typerecov` | 14 |
| **totale** | **59** |

### I 59 classificati, non assunti

- **18** in `sig_file_loader` e `ida_sig_compat` sono `raw[a..b].try_into().unwrap()`:
  l'unwrap e' infallibile (4 byte in `[u8; 4]`) e la fetta e' controllata a monte,
  cosa che gli sweep su input ostile di T11 hanno gia' esercitato senza panic.
- Le `.min()/.max().unwrap()` in `match_validator` stanno **dopo** un ritorno
  esplicito su `candidates.is_empty()`, e quelle successive operano su un insieme
  filtrato per uguaglianza col massimo, quindi non vuoto per costruzione.
- Quelle in `batch_applicator` sono avvelenamento di mutex.
- **Una** e' un contratto d'API, non input ostile: `FlirtSig::new` asserisce
  `pattern_bytes.len() == mask.len()`. Verificato: tutti i **19** chiamanti
  passano letterali, nessun parser costruisce i due vettori separatamente.
  Lasciata com'e' — trasformare l'errore di programmazione di un chiamante in un
  `Result` diffonderebbe rumore, non sicurezza.

### Una discrepanza di 3, che valeva la pena inseguire

Il gate in Rust contava **62** dove il mio script ne contava 59. Non era un
errore di uno dei due: la ricerca a sottostringa faceva combaciare `assert_eq!`
**dentro** `debug_assert_eq!`. E i `debug_assert*` non panicano in release, che e'
l'unica modalita' in cui questo progetto builda — contarli avrebbe gonfiato la
cifra con costrutti che nessun binario spedito puo' eseguire. Esclusi
esplicitamente: 62 - 3 = 59.

**Limite dichiarato nel test**: conta sintassi, non raggiungibilita'. Non
distingue un `unwrap` protetto da uno esposto; serve a far **notare e
classificare** i nuovi, non a certificare gli esistenti.

**Test: 2191 passati, 0 falliti, 0 target FAILED** — per crate
(527 + 559 + 780 + 325), ciascuno con exit 0. Build release pulita.

## 2026-07-30 — Iterazione 67 (T23: il numero era gonfiato ~14x, e i cast erano gia' protetti)

### Il conteggio

Il TODO diceva "clippy typerecov: 197". Misurato filtrando ai soli file sotto
`crates/rustre-analysis-typerecov/src/`: **14**.

Il 197 sommava due contaminazioni, entrambe gia' incontrate in questa sessione:
i **test** (come i "55 unwrap" che erano 9, e i "416" che erano 50) e i warning
di **altri crate** compilati nella stessa run — i primi cast `f64 -> u64` che ho
esaminato erano in `rustre-events`, non qui. Stavo per inseguirli.

Ripartizione dei 14: **10 cast con perdita** (4 wrap-around, 4 troncanti, 2 di
segno), tutti in `mem_access_scanner.rs`; 2 `if` collassabili; 1 `const fn`;
1 `use of`.

### I cast erano gia' protetti — e questo andava verificato, non letto

Ogni restringimento ha la sua guardia: `disp < 0 || disp > u32::MAX` prima del
cast a `u32`, `scale` filtrato su `{1,2,4,8}` prima del cast a `u8`, dimensione
clampata a 64. Leggerlo pero' non e' verificarlo, e la funzione in questione,
`scan_array_accesses_x86`, prende **byte grezzi** con un indirizzo base: e'
disassemblaggio di un binario non fidato.

E' la stessa classe di T24 ma con esito opposto: li' le guardie erano scritte
come panic (difetto), qui sono controlli di intervallo (corretti). La differenza
non si vede contando i warning — si vede leggendo cosa protegge cosa.

Verificate eseguendo: 4 test con stream costruiti per raggiungere i percorsi di
restringimento (displacement al limite di `u32`, displacement negativo se letto
con segno, tutte le codifiche di scale SIB, run di `0xFF` e `0x00`), uno stream
pseudo-casuale **deterministico** (nessun seme dall'orologio, cosi' un
fallimento e' riproducibile), e troncamento a ogni offset. Piu' un guard di
vacuita': se nessuno stream decodificasse, ogni assertion varrebbe a vuoto.

Nessun valore fuori dagli intervalli documentati. **Nessuna modifica al codice di
produzione**: i cast restano, ora coperti da test che li esercitano.

**Test: 2195 passati, 0 falliti, 0 target FAILED** — per crate
(527 + 559 + 780 + 329), ciascuno con exit 0. Build release pulita.

## 2026-07-30 — Iterazione 68 (T2: 106 erano 18, e 17 sono stile)

Applicata ai tre crate FLIRT la stessa misura corretta di ieri. Filtrando ai soli
`src/` dei rispettivi crate:

| crate | grezzo | in produzione |
|---|---|---|
| `rustre-flirt` | 89 | **5** |
| `rustre-flirt-gen` | 92 | **3** |
| `rustre-flirt-apply` | 144 | **10** |
| **totale** | | **18** |

Non 106. Stessa doppia contaminazione di T23 (dove 197 erano 14): i test e i
warning di **altri crate** compilati nella stessa run.

**17 dei 18 sono stile** — `const fn`, backtick mancanti, `sort_by_key`, una
funzione di 215 righe che e' una tabella dati. L'unico con profilo di difetto,
`casting u16 to u8`, e' **l'algoritmo stesso**: un CRC table-driven tronca al
byte basso per definizione. Ed e' gia' unificato a `flirt_tail`, con il commento
che documenta la correzione e un test che pinna l'accordo su tutti i 256 byte —
fatto in un'iterazione precedente.

**Quindi niente da correggere per correttezza.** Ho preso solo cio' che porta
significato: `#[must_use]` su `publish_resolved_matches`. Le sue `BridgeStats`
sono **l'unico** segnale che qualcosa sia arrivato alla type recovery: una corsa
in cui nessun nome ha un prototipo restituisce `published: 0` ed e' altrimenti
indistinguibile da una riuscita — ed e' esattamente cosi' che "il ponte funziona"
e' rimasto non messo in discussione fino a quando non l'ho misurato. Ora
ignorarlo e' un warning di compilazione. Piu' `#[must_use]` su `crc16_fast` (un
checksum calcolato e buttato e' sempre un bug) e `is_multiple_of`.

3 test, incluso l'invariante `considerate == pubblicate + scartate`: se smettesse
di tornare, un'identificazione si perderebbe senza che nessuna categoria la
registri.

**Test: 2198 passati, 0 falliti, 0 target FAILED** — per crate
(527 + 559 + 783 + 329), ciascuno con exit 0. Build release pulita.

## 2026-07-30 — Iterazione 69 (T36: il quinto sito sul layout sbagliato, e il modulo "compat" non era compatibile)

`ida_sig_compat` decodificava un layout tutto suo: campo nome **fisso a 64 byte**
in 22..86, header minimo 88 byte. Il layout pubblicato ha il nome **ultimo**,
preceduto dalla sua lunghezza a offset 34.

Misurato: dato un header prodotto dal codec canonico — 61 byte, il formato che
questo workspace **scrive** e dichiara di leggere — `IdaSigHeader::parse`
restituiva `Truncated`. Il modulo che porta "compatibilita' IDA" nel nome era
l'unico componente incapace di leggere un header in formato IDA.

Ora delega a `rustre_flirt::sig_header`. Dopo: nome, versione, arch, conteggio
funzioni e offset di fine header tutti corretti.

**Due cose rimosse oltre al codice.** Le costanti `MAGIC` e `HEADER_FIXED_SIZE`
(quest'ultima codificava i 64 byte fissi): una costante che afferma
un'invariante falsa e' peggio di nessuna costante, perche' il lettore successivo
la prende per documentazione. E il doc del modulo, che descriveva ancora il campo
a 22..86 sotto il codice che non lo implementa piu'.

**Sesta occorrenza dello stesso schema.** Il test che copriva questo parser,
`ida_sig_header_parse_v9_smoke`, scriveva a mano `buf[22..26] = "demo"` e
asseriva `cur >= 88`: costruiva lo stesso layout sbagliato che il parser leggeva,
quindi passava. Riscritto per costruire i byte **col codec canonico** e
confrontare `cur` con `h.len_bytes()` invece che con una costante ereditata.

**I cinque siti, per memoria**: T27 ne corresse due (writer e loader),
l'iterazione 43 trovo' `parse_sig_header`, la 45 `load_sig_file`, questa
`ida_sig_compat`. Ogni copia locale era internamente coerente — ed e' per questo
che nessuna falliva i propri test.

**Test: 2202 passati, 0 falliti, 0 target FAILED** — per crate
(527 + 559 + 787 + 329), ciascuno con exit 0. Build release pulita.

## 2026-07-30 — Iterazione 70 (T27: la conversione degli asset, misurata sul round-trip)

I 5 `assets/*.sig` sono tutti in `RFLIRTBIN` — 13 MB di firme generate in un
container che nessuno legge sul percorso di decompilazione. Il convertitore
verso `IDASGN` esisteva gia'; quello che mancava era la verifica che il
**contenuto** sopravviva, non solo che il file venga scritto.

Convertito `assets/rust-stdlib.sig` (10.8 MB) e riletto:

| | valore |
|---|---|
| pattern convertiti | 67 168 |
| firme rilette | **67 168** |
| nomi distinti | 66 943 |
| con wildcard | **31 533** |
| con CRC | 49 780 |
| lunghezza media | 30.7 byte |

Round-trip esatto. **Il numero che conta e' quello sui wildcard**: prima
dell'iterazione 53 il container troncava ogni pattern al primo wildcard, quindi
quei 31 533 — il **47%** del database — sarebbero arrivati come prefissi esatti
corti, che e' esattamente come una chiave di 3 byte finisce per combaciare con un
binario Go. E la lunghezza media di 30.7 byte contro un tetto di 32 dice che i
pattern arrivano interi, non tagliati.

E' la conferma su scala reale della correzione dell'iterazione 53, che fin qui
era stata misurata su `libz.a` (132 pattern).

**Resta una decisione, non un lavoro**: se committare i `.sig` convertiti o
generarli come passo di build. Sono 8.7 MB per il solo rust-stdlib.

**Nota di ambiente**: iterazione lenta per contesa sul lock di build — piu'
comandi in timeout e ripetuti, e `rustre-demangle` di nuovo rotto da edit
concorrenti (si e' risolto da solo al secondo tentativo, come da prassi del
repo). Nessun numero pubblicato da una run troncata.

**Test: 2205 passati, 0 falliti, 0 target FAILED** — per crate
(527 + 559 + 790 + 329), ciascuno con exit 0. Build release pulita.

## 2026-07-30 — Iterazione 71 (T17c: la circolarita' smette di essere un avvertimento)

T17c diceva: "`fidelity_arity.py` non e' piu' un oracolo indipendente, misurare
l'arieta' contro la stessa fonte e' tautologico". Vero, ma un avvertimento non
dice **quanto**. Misurato:

| | conteggio |
|---|---|
| nomi in `prototypes.json` | 136 |
| prototipi pubblicati dal ponte | 227 |
| **in comune** | **126** |
| quota della ground truth | **92.6%** |
| genuinamente indipendenti | **10** |

La metrica e' circolare per **piu' di nove nomi su dieci**. La sua cifra
(122/135) afferma, per quelli, che un file concorda con se stesso. Restano dieci
nomi su cui un controllo di arieta' dice qualcosa che l'emettitore non sapeva
gia': `_FindPESection`, `_GetPEImageBase`, `_IsNonwritableInCurrentImage`,
`__chk_fail`, `__mingw_GetSectionForAddress` e altri cinque.

**Un errore di misura mio, colto prima di pubblicare.** La prima versione
estraeva i nomi cercando `": "` nel testo e contava **139** dove il file ne ha
**136**: un errore del 2% nel denominatore del rapporto che l'esempio esiste per
affermare. Sarebbe diventato "90.6%" invece di 92.6%. Ora usa `serde_json`. E'
la stessa lezione dei conteggi clippy e dei test: il parser della misura va
guardato con lo stesso sospetto del codice misurato.

**Perche' un test e non un commento**: una nota nel TODO la legge chi apre il
TODO. Il test fallisce quando la sovrapposizione si muove — se qualcuno aggiunge
prototipi, l'indipendenza si riduce ancora, ed e' esattamente il momento in cui
qualcuno deve saperlo. Un altro dei tre verifica che la provenance dichiari
ancora gli header mingw: se la fonte cambiasse, la circolarita' andrebbe
rimisurata, non assunta.

**Test: 2208 passati, 0 falliti, 0 target FAILED** — per crate
(527 + 559 + 793 + 329), ciascuno con exit 0. Build release pulita.

## 2026-07-31 — Iterazione 72 (T18: la demo, e un README che spiega come non farsi ingannare dai numeri)

`examples/flirt_demo.rs` percorre la catena intera in un processo e stampa cosa
produce ogni stadio. Con `libmingw32.a` contro un binario C del corpus:

| stadio | valore |
|---|---|
| archivio | 31 membri, 31 oggetti -> **43 pattern** (34 con wildcard) |
| `.sig` scritto | 3078 byte, magic `IDASGN` |
| firme rilette | **43 su 43** |
| identificate sul target | **24** |
| identificate sul controllo | **0** |

**La colonna di controllo e' cio' che rende la demo un'affermazione invece che
una dimostrazione.** Produrre nomi e' facile; il fatto che *nessuno* compaia in
un binario Go, che quelle funzioni non puo' contenere, e' la parte verificabile.
E le due cifre si muovono insieme: all'iterazione 47 il controllo ne mostrava 5,
prodotti dai pattern che il container troncava al primo wildcard.

**Il README non descrive solo come si esegue: descrive come si leggono i
numeri.** Tre trappole gia' pagate in questa sessione, ciascuna con lo strumento
che la evita:
- il recall va misurato contro cio' che il binario **contiene**, non contro il
  numero di firme (522 firme -> 4 nomi sembrava l'1%, ma il tetto era 3);
- l'auto-riconoscimento serve a provare che qualcosa e' **rotto**, non che
  funziona: e' l'input piu' favorevole possibile;
- senza un binario di controllo un match non si distingue da un falso positivo.

Piu' la nota su `RUSTRE_SIGDB_DIR`: carica **tutte** le `.sig` della cartella, e
un file dimenticato di una sessione precedente ha gia' contaminato una misura
(iterazione 57).

4 test in `tests/demo_chain_end_to_end.rs`. Quello sul controllo e' il piu'
importante: se tornasse a trovare nomi, la demo continuerebbe a stampare 24
identificazioni sul target sembrando sana.

**Test: 2212 passati, 0 falliti, 0 target FAILED** — per crate
(527 + 559 + 797 + 329), ciascuno con exit 0. Build release pulita.
**Nota di ambiente**: molte run in timeout per contesa sul lock, ripetute fino a
completamento; nessun numero pubblicato da una run troncata.

## 2026-07-31 — Iterazione 73 (T19 misurato, non implementato; sessione fermata dall'utente)

Misurati gli item pubblici senza documentazione. `missing_docs` non e' attivo in
nessuno dei quattro crate:

| crate | mancanti |
|---|---|
| `rustre-flirt` | **275** |
| `rustre-flirt-gen` | **220** |
| `rustre-flirt-apply` | **218** |
| `rustre-analysis-typerecov` | **111** |
| **totale** | **824** |

**Una trappola di misura, colta prima di pubblicare.** La prima esecuzione ha
riportato **0 mancanti** per typerecov. Non era vero: senza toccare `lib.rs` la
compilazione e' in cache e il lint non gira affatto. Con `touch`: 111. Avrei
pubblicato "documentazione completa" su un crate con 111 item non documentati —
la stessa forma degli altri errori di misura di questa sessione, dove lo
strumento taceva e il silenzio sembrava un risultato.

**Non ho implementato, e la ragione e' una decisione, non pigrizia.** Scrivere
824 doc-comment e' lavoro di volume con poco valore di verifica, e soprattutto
si scontra con T8: **30 moduli pubblici non hanno alcun uso nel workspace**.
Documentarli tutti significherebbe scrivere commenti per codice che nessuno
chiama, e cementarlo come API supportata proprio mentre e' in attesa di una
decisione sul cancellarlo. L'ordine sensato e' T8 prima, T19 poi, sull'API che
resta.

**Stato a fine sessione: 2212 test verdi, 0 falliti** (iterazione 72, misurati
per crate). Build release pulita.
