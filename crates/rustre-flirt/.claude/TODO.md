# TODO — 4 crate (FLIRT x3 + typerecov), ordinato per valore/rischio

Stato: `[ ]` da fare · `[~]` in corso · `[x]` fatto+verificato · `[!]` bloccato

## Fase 0 — Baseline verde (prerequisito a tutto)

- [x] **T0** `cargo test --release` sui 3 crate → 1 fallimento
  (`rustre-flirt::tests::test_crc16_empty`). Il commento del test dichiarava
  CRC-16/X-25 (xorout 0xFFFF) mentre l'implementazione è MCRF4XX (no xorout);
  test corretto a 0xFFFF, coerente con `rustre-flirt-apply::crc16_flirt`.
- [!] **T1** ⚠️ **BLOCCATO — serve ground truth esterna.** IDA flair `crc16.cpp`
  ritorna `0` quando `len == 0`; le nostre due impl ritornano `0xFFFF`.
  Verificato che nel repo **non esiste nessun `.sig` in formato IDA**: i 5 file
  in `assets/*.sig` hanno magic `RFLIRTBIN`, cioè il *nostro* formato. Quindi la
  compatibilità IDA non è mai stata testata contro un artefatto reale (vedi
  anche T15, che diventa più importante di quanto sembrasse).
  **Per sbloccare:** serve un `.sig` prodotto da flair/`sigmake`, oppure i
  vettori di `crc16.cpp`. Finché manca, non dichiarare compatibilità IDA.
- [x] **T2** ✅ **Chiuso (iterazione 68): anche qui il numero era gonfiato.**
  Filtrando ai soli `src/` dei rispettivi crate: **18 warning in produzione**
  (flirt 5, gen 3, apply 10), non 106. Il resto erano test e warning di **altri
  crate** compilati nella stessa run — stessa doppia contaminazione di T23, dove
  197 erano 14.
  **17 su 18 sono stile** (`const fn`, backtick, `sort_by_key`, una tabella dati
  da 215 righe). L'unico con profilo di difetto — `casting u16 to u8` in un
  CRC — **e' l'algoritmo stesso** (CRC table-driven che tronca al byte basso),
  gia' unificato a `flirt_tail` e pinnato da un test in un'iterazione precedente.
  Applicate solo le correzioni che portano significato: `#[must_use]` su
  `publish_resolved_matches` (le sue `BridgeStats` sono **l'unico** segnale che
  qualcosa sia arrivato alla type recovery: `published: 0` e' indistinguibile da
  un successo, ed e' cosi' che "il ponte funziona" e' rimasto non messo in
  discussione per iterazioni) e su `crc16_fast`, piu' `is_multiple_of`.
  3 test in `rustre-flirt-apply/tests/bridge_stats_cannot_be_ignored.rs`,
  incluso l'invariante `considerate == pubblicate + scartate`.
  Vecchia voce: baseline **106 warning** su
  `--release --all-targets` (pedantic incluso). Due erano **bug veri, corretti**:
  `if_same_then_else` in `rename_propagator.rs` (prototipi libc errati) e
  `overly_complex_bool_expr` in `pat_writer.rs` (test vacuo). Resta il grosso:
  21 confronti f32/f64 esatti, 8+3+5+3 cast troncanti (`u64→usize`, `usize→u16`,
  `u64→u8`, `i32→u64`) — questi ultimi confluiscono in T10/T12 perché sono
  raggiungibili da input non fidato, non solo stile.

## Fase 1 — De-duplicazione (D3, D4) — il debito più grosso

- [x] **T3** ✅ **Fatto — e ha scoperto un bug di correttezza, non solo debito.**
  Le implementazioni erano **11**, non 7, e non erano copie dello stesso
  algoritmo: lo stack era spaccato in due metà incompatibili (dettaglio in
  `PROGRESS.md`). Ora esiste `rustre-flirt/src/crc.rs` con 4 primitive
  documentate (`mcrf4xx`, `x25`, `arc`, `cms`) + l'alias `flirt_tail`, pinnate
  ai check value di catalogo; tutti gli 11 siti delegano lì.
  Restano da unificare i **derivati**, non i primitivi: vedi T3b.
- [x] **T3b** ✅ **Fatto (iterazione 39), deciso per misura come previsto.**
  La domanda che lo bloccava era "quel valore finisce nello stesso campo?".
  Risposta misurata: **sì per costruzione, no di fatto**.
  - Sì: `OptimizedPattern` porta esattamente la terna del leaf `.sig`
    `(crc_offset: u16, crc_len: u8, crc: u16)`, e il generatore reale
    (`PatternGenerator::generate`) la riempie con `crc16_flirt`. Stesso campo.
  - No: `pattern_optimizer` è dichiarato in `lib.rs` e **importato da nessuno**
    nel workspace — nessun `.sig` ha mai trasportato un valore prodotto lì.
  Quindi `arc` → `flirt_tail`, più il commento che dichiarava "CRC-16/ARC —
  FLIRT standard" (falso: lo standard di questo stack è `flirt_tail`).
  **Neutralità provata, non assunta**: il round-trip di T14 dà righe identiche
  prima e dopo (65.2% / 78.3% / 11.5% / 97.0% / 84.6%).
  4 test in `rustre-flirt-gen/tests/pattern_optimizer_uses_the_canonical_crc.rs`,
  incluso uno che verifica che la *scelta della finestra* non dipenda dal
  polinomio — se dipendesse, il cambio non sarebbe neutro.
- [x] **T3c** ✅ **PROVATO nell'iterazione 38 tramite T14.** Le tre regole di
  mascheratura (generatore **scarta**, validatore **azzera**, `scan_fast` **non
  maschera**) non erano solo divergenti: costano match reali. Round-trip
  generate→scan su `libz.a` (132 pattern dal harvester reale, 26 con wildcard):
  auto-riconoscimento **65.2%** (86/132); azzerando il solo campo CRC **97.0%**
  (128/132). Sul sottoinsieme con wildcard **11.5% → 84.6%**. Un campo recupera
  42 dei 46 persi. Non e' un difetto di matching dei wildcard: i wildcard sono
  solo dove si concentrano le rilocazioni.
  Strumento: `examples/self_match_experiment.rs`. Meccanismo fissato in
  `tests/self_match_round_trip.rs` (3 test) piu' i 6 di
  `tests/crc_masking_divergence.rs`.
  ✅ **CHIUSO DAVVERO nell'iterazione 54.** La causa era che
  `crc_over_stable_region` saltava i byte mascherati ovunque nella finestra
  (byte hashati **non contigui**) mentre lo scanner ne legge `crc_len`
  **contigui**. Ora la finestra si ferma al primo byte mascherato: `crc_len`
  significa la stessa cosa sui due lati e i due concordano per costruzione.
  Auto-riconoscimento con CRC: 65.2% -> 73.5% (iter. 53) -> **97.0%**, cioe'
  identico alla baseline senza CRC. Senza wildcard: **100.0%**.
  2 test in `rustre-flirt-apply/tests/crc_no_longer_costs_matches.rs`.
  **Resta aperto**: i 4/132 che falliscono anche senza CRC (difetto separato, non
  attribuito) e quale regola usi IDA — serve ancora un `.sig` di flair (T1/T15).
  Descrizione originale:
  `pattern_extractor::CrcTail::compute` **scarta** i byte mascherati
  (accorciando il buffer), `match_validator::compute_flirt_crc` li **azzera**
  (mantenendo la lunghezza). Producono sequenze di byte diverse, quindi CRC
  diversi, anche ora che l'algoritmo è lo stesso. Da risolvere con T14.
- [x] **T39** ✅ **CONFUTATO per comportamento (iterazione 40). Nessuna modifica
  necessaria.** L'arm vuoto `TypeConstraint::Deref { .. } => {}` a
  `rustre-analysis-type/src/lib.rs:437` **non** scarta informazione: è
  deliberato. Deref è gestito da un pass dedicato che gira **dopo** la
  risoluzione di tutti gli `Equal`, iterato a punto fisso; derivare i tipi
  puntatore inline, a metà unificazione, rendeva il risultato dipendente
  dall'ordine dei vincoli. `solve_checked` riporta anche se il punto fisso ha
  convergiuto invece di troncare in silenzio.
  Verificato **eseguendo il solver**, non leggendo il commento (che potrebbe
  descrivere un'intenzione non più implementata): 5 test in
  `rustre-analysis-typerecov/tests/deref_constraints_are_not_discarded.rs` —
  puntatore derivato, indipendenza dall'ordine, Deref prima del pointee, catene
  a due livelli non appiattite, ciclo riportato come non-convergente.
  I test stanno in `typerecov` (che dipende da `rustre-analysis-type`), così il
  comportamento è fissato dal lato consumatore senza toccare un crate altrui.
- [~] **T37** **52 tipi pubblici duplicati**, ora **classificati** (iterazione
  41): **50 divergenti** (campi diversi) e **2 congruenti**. Inventario in
  `tests/duplication_inventory.rs`, classifica in
  `tests/duplicate_types_ranked_by_divergence.rs` (5 test).
  ⚠️ **50 non sono 50 difetti.** Divergente e' necessario ma non sufficiente:
  `Confidence` e' un enum in typerecov e una struct in `flirt_applicator`,
  `CollisionResolver` una strategia in un crate e una tabella di pesi in un
  altro — collisioni di nome fra moduli, che Rust gestisce e che nessuno puo'
  scambiare. Il sottoinsieme dannoso e' quello che modella lo **stesso
  concetto**.
  **Primo bersaglio affrontato (iterazione 42): `CoffSection`/`CoffSymbol`, i
  due decoder COFF dentro `rustre-flirt-gen`. Ha rivelato un bug vero, non solo
  debito.** I due divergevano sulla decodifica del **nome**:
  `library_scanner` tronca al primo NUL (semantica COFF corretta),
  `pattern_extractor` faceva `trim_end_matches('\0')`, che strippa solo i NUL
  *finali*. Misurato: sugli stessi byte `.text\0AB` uno dava `".text"`, l'altro
  `".text\0AB"` — una `String` con NUL interno e spazzatura in coda.
  Le due regole coincidono sugli oggetti emessi da un linker, per questo non era
  mai emerso; ma `flirt-gen` ingerisce `.lib` di terze parti, e lo stesso
  difetto era anche sui **nomi dei simboli**, che diventano i nomi delle firme
  emesse. Corretto con `coff_short_name`, un helper unico.
  5 test in `rustre-flirt-gen/tests/the_two_coff_decoders_agree.rs`; neutralita'
  verificata col round-trip di T14 (righe identiche).
  **Restano da unificare i due tipi** (non solo farli concordare): quando
  accadra', tenere quello di `pattern_extractor` — e' il superset e usa i nomi
  di campo pubblicati PE/COFF.
  **Secondo bersaglio (iterazione 43): `SigHeader` x5 — un altro bug vero.**
  `rustre_flirt::parse_sig_header` era ancora sul layout sbagliato: metteva
  `alt_ctype_crc` e `n_functions` DOPO il nome a lunghezza variabile, mentre il
  layout pubblicato li ha a offset fissi 35 e 37 col nome a 43. Misurato su un
  header prodotto dal codec canonico: restituiva 8 byte di spazzatura seguiti
  dal nome troncato invece di `"libz mingw64 build"`, e dichiarava l'header
  2 byte piu' corto, quindi tutto cio' che segue veniva letto disallineato.
  E' su un percorso vivo: `flirt_database` parsa blob reali via
  `FlirtSigFile::parse`.
  T27 aveva corretto "entrambi i lati": questo terzo sito era stato mancato, e
  il suo unit test costruiva a mano lo stesso layout sbagliato, certificandolo.
  Ora `parse_sig_header` delega a `sig_header::SigFileHeader::decode` e il test
  costruisce i byte col codec canonico.
  5 test in `rustre-flirt-apply/tests/all_sig_header_decoders_agree.rs`.
  ATTENZIONE — **deliberatamente NON toccato**: il ramo legacy `0x54 0x4A`,
  isolato in `parse_legacy_tj_header`. Usa la stessa forma misurata sbagliata
  per IDASGN, quindi e' probabilmente sbagliato anche li' — ma "probabile" non
  e' una misura, non esiste un `.sig` di flair nel repo per verificarlo, e sta
  su un percorso vivo. Appartiene a T1/T15.
  **Terzo bersaglio (iterazione 45): i due `FlirtPattern` (T29). Due difetti
  misurati piu' una decisione di semantica.**
  Traversata reale: generatore -> `SigWriter` -> `.sig` -> `load_sig_file` ->
  `FlirtSignature` -> `FlirtPattern::from_signature`. 5 test in
  `rustre-flirt-apply/tests/flirt_pattern_crosses_the_type_boundary.rs`.
  1. **`load_sig_file` recuperava 1 firma su 3** dagli stessi 169 byte in cui
     `from_sig_bytes` ne trovava 3: calcolava l'inizio del trie col layout
     vecchio (nome a 32 invece di 43), sfasato di 9 byte. QUARTO sito sul layout
     sbagliato. Ora delega a `SigFileLoader`, che usa `header_len()`. Misurato
     dopo: 3 su 3. Strumento: `examples/two_sig_readers.rs`.
  2. **Il container `.sig` non rappresenta i wildcard**: `SigWriter::build` fa
     `take_while(Exact)`, quindi un pattern di 16 byte con wildcard a 3..7
     attraversa come pattern di **3 byte**. Deliberato, ma silenzioso, e il
     round-trip di T14 non poteva vederlo perche' scansiona gli stessi byte da
     cui il pattern viene, dove un prefisso esatto combacia comunque.
     Rilevante per T3c: e' una spiegazione dell'11.5% sui wildcard.
  3. **`crc_offset` ha due convenzioni** (inconsistenza gia' annotata nel
     codice): `scan_fast` lo legge RELATIVO alla fine del pattern, mentre
     `Disambiguator::check_crc` e i produttori in `ida_sig_compat` lo trattano
     come ASSOLUTO. La traversata produce 0, cioe' la relativa. Fissato come
     misurato, non "corretto": ogni convenzione ha i suoi test verdi e la
     scelta e' di semantica voluta. **Serve una decisione.**
  Cio' che sopravvive intatto: nome e `crc_length` (u8 -> u16, allargamento).
- [ ] **T38** `flirt_matcher_v2` (786 righe) e `signature_matcher_new` (149)
  sono **codice morto**: referenziati solo dal proprio `pub mod`. Sono `pub`,
  quindi cancellarli e' un breaking change — decisione del maintainer.
  Tentata la deprecazione: ritirata, produceva 8 warning non silenziabili.
- [x] **T4b** ✅ **Chiuso (iterazione 48) — ed e' peggio di come era descritto.**
  La descrizione diceva "un `.pat` scritto per una parte dello stack non e'
  leggibile da un'altra". Misurata la matrice writer x parser
  (`examples/pat_writer_parser_matrix.rs`, 3 pattern: esatto, con wildcard, con
  CRC): **6 combinazioni su 6 recuperano ZERO righe**, compreso ogni writer
  accoppiato al parser del suo stesso crate.

  | writer \ parser | `apply::pat_parser` | `flirt::pat_v2` | `flirt::parse_pat_text` |
  |---|---|---|---|
  | `gen::pat_file_writer` | ERR | 0 | 0 |
  | `flirt::signature_writer` | ERR | 0 | 0 |

  Le righe prodotte hanno l'aspetto del `.pat` IDA canonico. Misurato due volte,
  con e senza le righe di commento, per non confondere "non gestisce l'header"
  con "non sa leggere la riga": falliscono entrambe (`InvalidHex` sul file
  intero, `InvalidLine` sulle sole righe dati).
  ⚠️ **CORREZIONE (iterazione 50): avevo concluso "i writer `.pat` sono di fatto
  write-only". Falso, e la correzione conta.** La matrice copriva i tre parser
  *pubblici*; ne esiste un **quarto, privato** — `parse_pat_line` in
  `flirt-apply/src/lib.rs`, raggiunto da `load_pat_file`/`load_auto`, cioe' il
  percorso reale. Quello legge il formato canonico: misurato **3 firme su 3**,
  wildcard conservati agli offset giusti, `crc_len`/`crc` intatti.
  Cio' che resta vero e' piu' ristretto: duplicazione e API pubblica fuorviante,
  **non** perdita di dati sul percorso che spedisce.
  5 test in `tests/pat_production_path_reads_our_output.rs`. 3 test in
  `rustre-flirt-apply/tests/pat_round_trip_is_broken.rs` (verdi: fissano il
  difetto, non lo risolvono).
  Descrizione originale: i 4 parser `.pat` accettano 3 formati diversi e
  nessuno e' comune a tutti.** `apply` vuole `:` prima di `crc_len` e decimali;
  `v2` vuole un campo `delta` extra; il classico IDA nessuno dei due. Un `.pat`
  scritto per una parte dello stack non e' leggibile da un'altra. Tabella
  completa nel doc di `tests/pat_and_archive_survive_hostile_input.rs`.
- [~] **T4** ⭐ **Primo passo fatto (iterazione 49): esiste un parser canonico e
  il round-trip si chiude.** `rustre-flirt/src/pat_canonical.rs` implementa il
  formato `.pat` IDA documentato — quello che entrambi i writer emettono e
  l'unico che un tool esterno (flair, sigmake, IDA) produce.
  Misurato: writer reale -> `pat_canonical::parse_text` -> **3 pattern su 3**,
  con nomi, wildcard agli offset giusti (3,4,5,6), `crc_length`, `crc16` e
  `pattern_length` intatti. Prima era 0 su 6.
  Diagnosi che ha deciso quale dialetto e' canonico, invece di sceglierlo a
  intuito: `apply::pat_parser` pretende `:` iniziale e `crc_len` **decimale**;
  `pat_parser_v2` pretende un prefisso noto su ogni nome piu' un campo `delta`;
  `SimpleFlirtDatabase::parse_pat_text` non accetta nessuno dei due **e scarta
  gli errori in silenzio** — per questo "zero pattern recuperati" sembrava un
  parsing riuscito. `pat_canonical` restituisce invece gli errori per riga.
  6 test in `rustre-flirt-apply/tests/pat_canonical_round_trip.rs`.
  **Deliberatamente additivo**: i tre parser dialettali sono intatti e i loro
  test restano verdi, quindi anche `pat_round_trip_is_broken.rs` resta verde —
  quei parser continuano a non leggere il nostro output, e resta registrato
  finche' non vengono davvero spostati.
  **Secondo passo (iterazione 51): misurato che non ci sono chiamanti da
  spostare.** I tre parser dialettali hanno **zero riferimenti in codice di
  produzione** nei 4 crate — esistono solo nei propri test. Il lettore che
  spedisce e' il quarto, privato, via `load_pat_file`. Verificato con un test che
  **enumera** i riferimenti (3 test in
  `tests/pat_dialect_parsers_have_no_production_callers.rs`), non con un grep:
  include un controllo positivo su `crc16_flirt` per escludere uno scanner vacuo,
  ed esclude i `#[cfg(test)]` inline dei file di produzione.
  ⚠️ **Lo scan vede solo dentro il workspace**: sono `pub`, quindi un chiamante
  esterno non e' escluso. La conclusione e' "sicuro consolidare *dentro* il
  workspace", non "sicuro cancellare".
  **DECISIONE RICHIESTA (la quarta)**: farli delegare a `pat_canonical` cambia il
  formato accettato da API pubbliche e fa fallire i loro test dialettali, che
  codificano formati che nessuno usa e che nessun tool esterno produce. E' un
  breaking change: stessa classe di T38, quindi non la prendo da solo.
  Descrizione originale: collassare i parser `.pat`: `flirt/pat_parser.rs` +
  `flirt/pat_parser_v2.rs` + `apply/pat_parser.rs`. Un solo parser, gli altri
  re-export.
  **Criterio di successo ora misurabile** (da T4b, iterazione 48): oggi la
  matrice writer x parser da' 0 su 6. Dopo T4 deve dare 3 righe recuperate per
  ogni cella, e il test `pat_round_trip_is_broken.rs` deve FALLIRE — e' scritto
  apposta per fallire quando il difetto e' risolto, con il messaggio che lo dice.
  **Decisione richiesta prima di iniziare**: quale dialetto e' canonico. Le tre
  varianti hanno ognuna i propri test verdi, quindi sceglierne una ne rompe
  altri. Il candidato ragionevole e' il `.pat` IDA classico, che e' gia' quello
  che i due writer producono.
- [~] **T5** Collassare i matcher: `signature_matcher.rs`,
  `signature_matcher_new.rs`, `sig_matcher.rs`, `flirt_matcher_v2.rs`.
  Decidere il vincitore **con un benchmark**, non a occhio.
  **Primo passo (iterazione 52): misurata la CORRETTEZZA prima della velocita'.**
  Un benchmark ordina per velocita', ma la velocita' conta solo fra
  implementazioni che danno la **stessa risposta**. Misurato `PatternMatcher`
  (16 byte in memoria) contro lo scanner di produzione, su pattern con wildcard:
  - su un buffer che contiene il pattern, **concordano** (offset 8) — ma non per
    lo stesso motivo: `PatternMatcher` onora la maschera su 16 byte, lo scanner
    combacia sul **prefisso di 3 byte** superstite al troncamento del container;
  - su un buffer che contiene solo quel prefisso e poi byte che **contraddicono**
    il pattern, divergono: `PatternMatcher` dice no (corretto), lo scanner dice
    si'. **E' un falso positivo riprodotto in cinque righe**, ed e' la stessa
    forma dei 5 falsi positivi misurati cross-binario su un binario Go.
  5 test in `tests/matchers_agree_on_where_a_pattern_matches.rs`.
  **Conseguenza per T5**: il "vincitore" non poteva essere scelto col benchmark
  finche' il container scartava i wildcard — si sarebbe misurata la velocita' di
  due cose che rispondono a domande diverse.
  ✅ **RIMOSSO IL BLOCCO (iterazione 53)**: il leaf `.sig` ora porta una coda
  mascherata (ctrl `0x02`), i due matcher vedono lo stesso pattern e il falso
  positivo minimo e' sparito.
  ✅ **BENCHMARK FATTO (iterazione 60), e cambia la domanda.** Misurato prima:
  **nessuno dei quattro candidati e' referenziato da codice di produzione** — cio'
  che spedisce e' `FlirtScanner::scan_fast`. Quindi "quale dei quattro vince"
  ordinerebbe quattro cose che nessuno chiama; la domanda utile e' se qualcuno
  batta quello che spedisce. Misurato su 2 MB, un'occorrenza piantata per firma:

  | firme | lineare | `scan_fast` | rapporto |
  |---|---|---|---|
  | 16 | 21.9 ms | 0.49 ms | **44x** |
  | 128 | 174 ms | 0.76 ms | **229x** |
  | 1024 | 1.46 s | 6.95 ms | **209x** |

  Conteggi degli hit identici a ogni taglia. Il divario cresce col database,
  com'e' atteso: lineare e' O(pattern x byte), l'indice e' ~O(byte).
  **Nessun candidato batte quello in produzione**, quindi T5 si riduce alla stessa
  decisione di API pubblica di T38 — cancellare o ridurre a re-export — e non a
  una scelta tecnica.
  `examples/matcher_benchmark.rs` + 2 test in
  `tests/matchers_find_the_same_occurrences.rs`.
- [ ] **T6** Collassare gli applier: `batch_applicator.rs`, `batch_applier.rs`,
  `bulk_applier.rs`, `flirt_applicator.rs`, `apply_engine.rs`.
  **Misurato (iterazione 61): `batch_applicator`, `batch_applier`,
  `bulk_applier` e `flirt_auto_apply` hanno ZERO riferimenti di produzione.**
  Come T4 e T5, si riduce alla decisione di API pubblica di T38, non a una scelta
  tecnica.
- [~] **T7** ⚠️ **La premessa e' sbagliata (misurato, iterazione 61): non sono
  due propagatori dello stesso concetto.** `name_propagator` percorre il call
  graph propagando nomi fra chiamante e chiamato; `rename_propagator` porta
  **firme di funzione con tipi C** e le applica. Entrambi **vivi** (4 e 3
  riferimenti di produzione). Collassarli fonderebbe due lavori diversi — lo
  stesso errore di trattare ogni nome duplicato come concetto duplicato.
  **Ricaduta su Level 7, verificata**: `rename_propagator::builtin_signatures()`
  sembrava una seconda fonte di prototipi che il ponte ignora. Misurato: le sue
  **88 firme sono un sottoinsieme stretto** delle 227 del ponte (0 uniche), e
  **0** dei 25 nomi combacianti senza prototipo e' coperto. Nessuna fonte
  inesplorata: risultato negativo, ma misurato.
  3 test in `tests/prototype_sources_do_not_diverge.rs`, incluso il confronto
  dell'**arieta'** sulle firme condivise, non solo dei nomi.
  Descrizione originale: collassare i propagatori di nomi: `name_propagator.rs` +
  `rename_propagator.rs`; e i resolver: `collision_resolution.rs` +
  `match_conflict_resolver.rs` + `disambig.rs`.
- [~] **T8** Superficie pubblica. **Misurata a livello di modulo (iterazione 62),
  e sostituisce quattro decisioni separate con una.**

  | | conteggio |
  |---|---|
  | moduli pubblici nei 4 crate | 70 |
  | usati da codice di produzione | 23 |
  | non usati dalla produzione | 47 |
  | …di cui usati da test/example | **17** (devono restare `pub`) |
  | **senza alcun uso nel workspace** | **30** |

  I 17 contano: test d'integrazione ed example sono crate separati e raggiungono
  solo item `pub`, quindi renderli `pub(crate)` romperebbe i test — decisione
  diversa dal cancellarli. **I 30 sono la lista azionabile**, e sussumono T4, T5,
  T6 e T38 in un'unica decisione del maintainer.
  ⚠️ Lo scan vede solo questo workspace: sono `pub`, quindi "non usato qui" non
  significa "sicuro da cancellare".
  2 test in `tests/dead_public_surface_does_not_grow.rs` (con controllo positivo)
  + `examples/dead_public_modules.rs` per la lista completa.
  Resta da fare: il conteggio per `pub fn` (998) e la dichiarazione esplicita
  dell'API supportata in `lib.rs`.

## Fase 2 — Robustezza / sicurezza (D5, D6, D10)

- [x] **T9** ✅ **I 3 `unsafe` non esistevano.** Erano la parola dentro commenti
  che dicevano "no unsafe" (`casts.rs`) — falso positivo del grep di baseline.
  Misurato: **0 costrutti `unsafe` in tutti e 4 i crate**. Aggiunto
  `#![forbid(unsafe_code)]` (non `deny`: aggirabile con `#[allow]` interno) a
  tutti e quattro, piu' 4 test — attributo presente, e' `forbid`, scansione
  diretta dei sorgenti, e un guard che verifica che lo scanner riconosca
  `unsafe` vero senza scattare sui commenti.
- [x] **T10** ✅ **Rimisurato: 50 in produzione, non 416.** I 416 erano quasi
  tutti in `#[cfg(test)]`, dove un panic e' corretto. Dei 50: ~20 sono
  `try_into().unwrap()` infallibili su slice a dimensione fissa, gia' protetti da
  guard di lunghezza a monte (verificato su `ida_sig_compat`); il resto sono
  mutex, `.max()` su collezioni non vuote per costruzione, ed `expect` su
  overflow u32 documentati. Nessuno raggiungibile da input non fidato — coerente
  con lo sweep ostile che non ne ha innescato nessuno.
  Vecchia descrizione:
  quelli raggiungibili da un `.sig`/`.pat`/COFF **malevolo** vanno a `Result`.
  Un `.sig` è input non fidato: arriva da terzi.
- [~] **T11** Sweep deterministico su input ostile per i **3 parser che ho
  scritto/rifatto**: header `IDASGN`, trie `.sig`, container `RFLIRTBIN`.
  Troncamento a ogni offset, corruzione di un byte a ogni offset (5 valori),
  saturazione dei campi di lunghezza a `0xFF`, e un file che dichiara
  `u32::MAX` pattern. **7 test, nessun panic.** Piu' un guard che verifica che
  il corpus mutato sia davvero valido (altrimenti lo sweep passerebbe a vuoto).
  **Iterazione 25:** coperti anche i 4 parser `.pat` e `coff_archive`
  (inclusa la forma archive-bomb: membro che dichiara 9 999 999 999 byte).
  **9 test in piu', nessun panic.** T11 chiuso per i parser di questi crate.
- [x] **T12** ✅ **Misurato: i tetti non servono.** 50 000 membri (3 MB) in
  **19 ms**, crescita lineare; una dimensione dichiarata di 9 999 999 999 byte
  viene respinta in 0 ms. Il parser ar limita ogni membro alla lunghezza reale
  del file. Un cap sul numero di membri **rifiuterebbe archivi legittimi**
  (un `.lib` vero ne ha decine di migliaia) per difendere da qualcosa di gia'
  limitato. Consegnato invece un **guard di regressione**: 5 test che falliscono
  se il costo diventa super-lineare, con soglie larghe per non essere instabili.
  **Non coperto:** il parsing di oggetti COFF/ELF reali (percorso costoso).
- [x] **T13** ✅ **Determinismo.** Trovata e corretta l'iterazione su `HashMap`
  in `coff_archive::harvest_object_bytes` (ordine sezioni casuale -> ordinato per
  indice). 7 test: writer byte-identico, conversione identica, filtro
  deterministico, il parser preserva l'ordine, stesso input -> stesso digest,
  harvest di archivio **reale** stabile, `.sig` da archivio reale identico.
  Nota: i `.lib` del corpus sono import library C# (0 oggetti) e non esercitano
  il codice — il test usa `libz.a` del toolchain, con skip se assente.

## Fase 2b — `rustre-analysis-typerecov` (4° crate, aggiunto 2026-07-28)

- [x] **T23** ✅ **Chiuso (iterazione 67), e il numero era gonfiato ~14x.**
  Il "197" contava i **test** e i warning di **altri crate** compilati nella
  stessa run. Filtrando ai soli `crates/rustre-analysis-typerecov/src/`:
  **14 warning in produzione**, di cui **10 cast con perdita** (4 wrap, 4
  troncanti, 2 di segno), tutti in `mem_access_scanner.rs`, piu' 2 `if`
  collassabili, 1 `const fn`, 1 `use of`.
  **I 10 cast sono gia' protetti**: `disp < 0 || disp > u32::MAX` prima del
  restringimento, `scale` verificato in `{1,2,4,8}`, dimensione clampata a 64.
  Ma leggere non e' verificare, e `scan_array_accesses_x86` prende **byte
  grezzi** da un binario non fidato: sono quelle guardie a separare
  un'istruzione costruita ad arte da un offset di campo senza senso — che non
  crasherebbe, produrrebbe un layout struct confidentemente sbagliato.
  4 test in `tests/scanner_guards_hold_on_hostile_bytes.rs`: stream costruiti per
  raggiungere i percorsi di restringimento (disp al limite u32, disp negativo con
  segno, tutte le codifiche di scale SIB, run di 0xFF/0x00), stream
  pseudo-casuale deterministico, troncamento a ogni offset, piu' un guard di
  vacuita'. Nessun valore fuori range.
  Vecchia voce: Clippy `typerecov`: 205 -> **197**. Triage fatto sui 428 totali dei
  4 crate: **una sola** categoria ha profilo di difetto (`match_same_arms`, 11),
  il resto e' stile o cast gia' triati in T10. Corretti 8 match arm
  irraggiungibili in `typevar_for_register` (vedi PROGRESS iterazione 32).
- [x] **T24** ✅ **Fatto (iterazione 63) — ma il numero era sbagliato e il difetto
  vero non era fra quelli contati.**
  Conteggio reale in **produzione**: **9**, non 55 (i 55 includono il codice di
  test — stesso sovra-conteggio gia' visto con i 416 unwrap). Contati tracciando
  i blocchi `#[cfg(test)]` per profondita' di graffe: tagliare al **primo**
  `#[cfg(test)]` ne dava 6, cioe' sotto-stimava, perdendo i 3 di `lib.rs`.
  **Il difetto raggiungibile era un `assert!`**, che nessuna ricerca di
  `unwrap|expect|panic` avrebbe trovato: `UnionFind::new` con
  `assert!(n <= MAX_NODES)`, sotto un commento che dice
  "Guard against OOM from an adversarially large var_count". Misurato:
  `TypeUnifier::new(16_777_217)` **abortiva il processo**. `var_count` deriva dal
  binario analizzato, quindi un file costruito ad arte abbatteva qualunque
  strumento basato sul crate — **andare in panic era il denial of service che la
  guardia doveva impedire**.
  Correzione additiva: `TypeUnifier::MAX_VARIABLES`, `TypeUnifier::try_new` e
  l'entry point `unify_types` restituiscono `UnifyError::TooManyVariables`;
  `new` resta e documenta di panicare.
  5 test in `rustre-analysis-typerecov/tests/hostile_var_count_does_not_panic.rs`,
  incluso il caso **al** tetto (un tetto che rifiuta il proprio limite perderebbe
  in silenzio l'input legittimo piu' grande).
  **Seconda meta' (iterazione 64): la correzione del costruttore copriva solo
  meta' del problema.** I vincoli portano i **propri** id di `TypeVar`, nascono
  dal binario e `solve` li passava dritti all'union-find. Misurato: un solo
  vincolo con `TypeVar(16_777_215)` **abortiva il processo** — e quell'id e'
  **sotto** il tetto, quindi non era nemmeno fuori range: lo faceva cadere la
  guardia anti-amplificazione, scritta come `assert!`. Controllare `var_count` da
  solo non l'avrebbe mai trovato.
  Ora `solve` valida ogni id prima di toccare l'union-find e pre-alloca a passi
  limitati. 4 test in `tests/hostile_constraint_ids_do_not_panic.rs`, incluso uno
  per **ogni forma** di vincolo (validare solo `Equal` lascerebbe le altre come
  via d'ingresso).
  ⚠️ **Regressione mia, colta e riparata**: la prima versione ragionava in id
  invece che in lunghezza, quindi `TypeUnifier::new(0).solve(&[])` allocava un
  nodo e `class_count` passava da 0 a 1.
  **Terza istanza (iterazione 65): `StructRecoveryEngine::record`/`record_all`.**
  Il doc diceva testualmente "preventing denial-of-service via memory exhaustion
  when analysing adversarially-crafted binaries" — e ci rispondeva con un
  `assert!`. Aggiunti `MAX_ACCESSES` pubblica, `try_record` e `try_record_all`
  che restituiscono `StructRecoveryError::TooManyAccesses`; le versioni che
  panicano restano e lo documentano.
  Secondo difetto rimosso dalla riscrittura: `record_all` asseriva **dentro** il
  ciclo, dopo aver gia' inserito parte dell'input — chi catturava il panic
  restava con un motore mezzo pieno e nessun modo di saperlo. `try_record_all`
  restituisce quanti ne ha registrati.
  4 test in `tests/field_access_cap_is_an_error.rs`.
  **Chiuso (iterazione 66) con un gate sull'intera classe.** Superficie di panic
  misurata in produzione (test esclusi per profondita' di graffe, `debug_assert*`
  escluso perche' non panica in release): flirt 4, gen 9, apply 32, typerecov 14
  = **59**. Classificati invece che assunti: 18 sono `raw[a..b].try_into()`
  con controllo di lunghezza a monte (gia' esercitati dallo sweep di T11), le
  `.min()/.max().unwrap()` stanno dopo una guardia `is_empty()` esplicita o su
  insiemi non vuoti per costruzione, altre sono avvelenamento di mutex.
  Una sola resta un contratto d'API e non input ostile: `FlirtSig::new` asserisce
  `pattern_bytes.len() == mask.len()`, e tutti i 19 chiamanti passano letterali —
  lasciata, documentata sotto `# Panics`.
  Gate in `rustre-flirt-apply/tests/panic_surface_does_not_grow.rs`.
- [x] **T25** ✅ **Proprieta' verificate.** 10 test in
  `tests/unifier_properties.rs`: riflessivita', simmetria, transitivita' (anche a
  profondita' 200), **indipendenza dall'ordine** (tutte le rotazioni cicliche +
  inverso), idempotenza sui duplicati, terminazione su ciclo, nessun tipo
  inventato senza vincoli, variabili fuori range senza panic, `class_count`
  limitato. Tutte verdi: le proprieta' ci sono, ora verificate invece che
  sperate.
- [x] **T26** ✅ **Degradazione sicura verificata — e un bug trovato.**
  `StructRecoveryEngine` derivava `Default`, ottenendo `pointer_width: 0` e
  `min_access_count: 0`: `recover_for` restituiva `Some` (struct a zero campi)
  per **ogni** variabile anche mai osservata, e `looks_like_pointer` non poteva
  mai scattare — il piolo "pointer" era morto in quegli engine. `Default` ora
  delega a `new_64bit()`. 11 test di degradazione in `tests/safe_degradation.rs`.

## Fase 3 — Prova che funziona davvero (D7, D8, D9)

- [x] **T14** ✅ **COMPLETO (iterazione 47): round-trip + cross-binario.**
  La seconda meta' e' fatta e ha cambiato la lettura di tutte le altre misure.
  `examples/cross_binary_match.rs` genera da `libmingwex.a` (522 pattern) e
  scansiona un binario mingw del corpus PIU' un binario Go come controllo:

  | sottoinsieme | target | estraneo (Go) |
  |---|---|---|
  | tutti (522) | 4 | **5** |
  | integri (371) | 1 | **0** |
  | troncati dai wildcard (151) | 3 | 5 |
  | ridotti <8 byte (27) | 3 | 5 |

  **Piu' nomi sull'estraneo che sul legittimo**, e tutti i falsi positivi vengono
  dai troncati. Ne segue che il recall reale e' **~1 su 522**, non 4.
  Sweep soglia: 0->(4,5), 4->(1,2), **8->(1,0)**, 16->(1,0), 24->(0,0).
  3 test in `rustre-flirt-apply/tests/cross_binary_specificity.rs`, **verdi**
  (saltano se mingw o il corpus mancano).

  Prima meta' (iterazione 38): il round-trip.
  `examples/self_match_experiment.rs` fa archivio reale → harvest → `.sig` →
  scan **sugli stessi byte da cui i pattern vengono**. E' l'input piu'
  favorevole possibile, quindi un fallimento li' e' un difetto puro, non un
  problema di soglie o falsi positivi. Ha chiuso T3c (vedi sopra).
  **Resta da fare**: la seconda meta', cioe' scan su un binario del corpus con
  asserzione sulle VA dei nomi noti (`_Unwind_GetIP`, `__acrt_iob_func`, …).
  Il round-trip prova che le firme funzionano su se stesse; non prova ancora
  che ritrovino la stessa funzione compilata in un *altro* binario.
- [ ] **T15** Cross-check con IDA: le nostre `.sig` devono essere caricabili da
  flair/IDA e le loro `.sig` da noi (round-trip binario).
- [x] **T16** ✅ **Benchmark + gate.** `examples/scan_benchmark.rs` per i numeri,
  `tests/scan_performance_does_not_regress.rs` per il gate (4 test, soglie larghe
  di proposito). Misurato: build 67 168 firme in **103 ms**, scan
  **149-235 MB/s**, 10x input -> 5.1x tempo, indice non ricostruito per chiamata.
  Niente criterion: dipendenza sproporzionata, e la sua precisione statistica
  sarebbe finta su una macchina con build concorrenti.
- [x] **T17a** ✅ **Il filo e' collegato.** Creato
  `rustre-flirt-apply/src/typerecov_bridge.rs`: traduce `TypeDescriptor` ->
  `RecoveredType`, converte un prototipo FLIRT in `FunctionSignatureRecord` e lo
  pubblica via `register_function_signature`. `rustre-flirt-apply` ora dipende da
  `rustre-analysis-typerecov` (nessun ciclo: typerecov non cita FLIRT).
  8 test, incluso l'end-to-end che parte da `Confidence::Low` e dimostra che una
  identificazione FLIRT produce una firma con arieta' e convenzione corrette.
  Regola fissata nel codice e nei test: se il nome non ha un prototipo
  pubblicato **non si pubblica nulla**, non si tira a indovinare.
- [x] **T17b** ✅ **Copertura da 0 a 125.** Prototipi estratti **meccanicamente**
  dagli header mingw-w64 installati con `tools/gen_runtime_prototypes.py` ->
  `rustre-flirt-apply/src/runtime_prototypes.rs` (file GENERATO, con
  header:riga per ogni voce). Nessun prototipo scritto a memoria.
  Misurato: prototipi nel bridge 88 -> **213**; copertura della ground truth
  **0/136 -> 125/147**; arita' concordi su tutti e 125.
  Le varianti variadiche sono escluse di proposito: una firma ad arieta' fissa
  non puo' combaciare con `...`, quindi pubblicarla asserirebbe il falso.
  Restano 22 non coperti (interni crt non presenti negli header pubblici:
  `_FindPESection`, `_GetPEImageBase`, `_pei386_runtime_relocator`, ...).
- [x] **T17d** ✅ **La presa GIUSTA, e il decompiler ora chiama il bridge.**
  Scoperto che avevo collegato la presa sbagliata: il registry di
  `rustre-analysis-typerecov` (`register/infer_function_signature`) **non e'
  letto da nessuno** in produzione. Il vero Level 7 e' in `rustre-analysis-type`
  (`infer_function_signature_named(addr, name, cc, env, &lib_db)`, commentato
  "§6.6 level 7", dove "published library prototypes win over inference").
  Fatto: `LibrarySignatureDb` estesa con i prototipi mingw generati
  (`mingw_runtime_sigs.rs`), e `binary_entry.rs::flirt_pairs_with_scanner` ora
  chiama `publish_identifications` DOPO il filtro di ambiguita'.
  Misurato: copertura della presa vera **3/136 -> 126/136**; voci in
  `LibrarySignatureDb` 70 -> 206. Test verdi 5 crate: **2577**.
- [x] **T17e** ✅ **Diagnosticato: causa radice trovata e misurata.**
  FLIRT trova 0 match perche' il decompiler ha in tutto **22 firme scritte a
  mano** (`msvcrt-x64.sigpack` 8 + `rust-stdlib-x64.sigpack` 14).
  Sotto c'e' un difetto piu' profondo: **tre formati di firma scollegati**
  (vedi PROGRESS.md e T27). 3 test lo fissano.
- [~] **T27** ⭐ **Conversione asset verificata (iterazione 70).** I 5
  `assets/*.sig` sono tutti in `RFLIRTBIN`, formato che nessuno legge sul
  percorso di decompilazione. Convertito il piu' grande e **misurato il
  round-trip**, non solo la scrittura:

  | | valore |
  |---|---|
  | pattern convertiti | 67 168 |
  | firme rilette | **67 168** |
  | nomi distinti | 66 943 |
  | con wildcard | **31 533** |
  | con CRC | 49 780 |
  | lunghezza media | 30.7 byte |

  Il dato sui wildcard e' quello che conta: prima dell'iterazione 53 il container
  troncava al primo wildcard, quindi quei 31 533 (**47% del database**) sarebbero
  arrivati come prefissi esatti corti — il modo in cui una chiave di 3 byte
  combacia con un binario Go. La media di 30.7 byte contro un tetto di 32 dice
  che i pattern arrivano interi.
  3 test in `tests/converted_assets_round_trip.rs` (su un asset piccolo, quindi
  autosufficienti) + `examples/asset_conversion_round_trip.rs` per i numeri.
  **Resta**: decidere se committare i `.sig` convertiti o generarli come passo di
  build — sono 8.7 MB per il solo rust-stdlib.
  Descrizione originale: header IDASGN corretto su ENTRAMBI i lati.
  | formato | scritto da | letto da |
  |---|---|---|
  | `SIGPACK 1` (testo) | a mano, 22 voci | lo scanner del decompiler |
  | `RFLIRTBIN` | bin `rust_stdlib_sigs` di flirt-gen | **solo** `rustre-gui` |
  | `IDASGN` | writer in `rustre-flirt/lib.rs` | `sig_file_loader` di flirt-apply |

  **Iterazione 9 — correzione a un'affermazione dell'iterazione 8.**
  Avevo scritto "il writer e' vicino al layout IDA, il loader e' la parte
  sbagliata". Falso: erano sbagliati **entrambi**, in punti diversi.
  - loader: leggeva `n_funcs:u32` a offset 34 (che e' `library_name_len:u8`) e
    prendeva il nome da una finestra fissa 40..104;
  - writer: metteva il nome **subito dopo** il byte di lunghezza, prima di
    `alt_ctype_crc` e `n_functions`.

  **Fatto:** entrambi portati al layout pubblicato
  (34 name_len:u8, 35 alt_ctype_crc, 37 n_functions:u32 v6+,
  41 pattern_size:u16 v8+, 43 nome). L'header e' **a lunghezza variabile**:
  `SigHeader::SIZE = 104` e' deprecata, sostituita da `header_len()`, e il trie
  ora parte da li' invece che da una costante — prima veniva letto dall'offset
  sbagliato per ogni libreria il cui nome non fosse esattamente 61 byte.
  Aggiunto rifiuto esplicito di `library_name_len` fuori dal buffer (un `.sig`
  e' input non fidato: troncare darebbe un'identita' di libreria plausibile e
  sbagliata).
  I 3 test tripwire sono stati **riscritti in positivo** e sono **verdi**:
  5/5 in `idasgn_writer_loader_roundtrip`. Totale 5 crate: **2585**.

  **Iterazione 10:** creato il codec canonico
  `rustre-flirt/src/sig_header.rs` (encode+decode, 8 test) — stessa forma del
  fix CRC: una sola definizione, tutti delegano. E2E verde: un `.sig` scritto da
  `flirt-gen::SigWriter` e' ora letto da `flirt-apply::SigFileLoader` (5 test).
  Erano **4 writer di header e 3 reader** su due layout incompatibili.

  **Iterazione 12:** trovato e corretto un **settimo** sito —
  `inspect_sig_header` leggeva 104 byte fissi da disco e degradava ogni header
  piu' corto a stub senza nome; piu' il trie start di `load_sig_file_v9` e
  l'helper di test `make_v9_sig_bytes`. 5 test nuovi in
  `variable_length_header_is_honoured.rs`. **1983 test verdi.**

  **Iterazione 11:** convertiti tutti i siti rimasti — `flirt-gen/lib.rs`,
  `pat_sig_format.rs` (serialize + deserialize + `SigFile`), `coff_archive.rs`,
  piu' un **sesto** parser emerso strada facendo
  (`flirt-apply/lib.rs::parse_sig_v9_header`). 11 test riscritti per
  **decodificare** invece di leggere offset fissi.

  **Iterazione 13:** aggiunti `FlirtScanner::from_sig_file`,
  `from_sig_bytes` e `from_packs_and_sig_files` — il percorso
  `.sig` -> scanner ora **esiste** (prima non c'era, ed era la ragione per cui il
  decompiler aveva solo 22 firme). I pack curati e un database generato si
  combinano, quindi adottare un `.sig` non fa perdere le voci verificate a mano.

  **Iterazione 17:** ✅ il decompiler carica i `.sig` binari da
  `RUSTRE_SIGDB_DIR`. Misurato su `sample3_rust.exe`: 22 -> 67 190 firme,
  0 -> 238 match, 59 file `.c` su 213 cambiano
  (`sub_140002620()` -> `__rustc_..._rdl_alloc()`). **T27 chiuso.**

  **Restano da fare:**
  1. [~] **T32** Precisione misurata contro il PDB del corpus: **88.2%**
     (limite inferiore, 15 presenti / 2 assenti / 10 non decidibili su 27 nomi).
     Strumento: `examples/match_precision_vs_pdb.rs`. Per stringere il limite
     serve leggere gli indirizzi `S_PUB32` con `rustre-symbols-pdb`, non solo
     i nomi. Domanda ancora aperta: 238 -> 20 dopo i
     filtri: quanti dei 218 scartati erano falsi positivi e quanti buoni persi
     per prudenza? Un falso positivo rinomina **male** una funzione, che e' il
     danno peggiore. Serve `behavior.py`, non l'arieta'.
  2. ✅ Convertire `RFLIRTBIN` -> `IDASGN`: fatto (modulo `rflirt_bin`, 9 test,
     piu' l'esempio `convert_rflirt_to_sig`). **67 168 pattern** convertiti dal
     database reale. Ma il valore non arriva finche' T31 non e' risolto.
- [x] **T30** ✅ **Encoder di trie unificati.**
  `sig_writer::SigWriter::build` ora delega a `rustre_flirt_gen::SigWriter`,
  cioe' all'unico encoding che il loader sa decodificare. Il tripwire e' stato
  riscritto in **positivo**: entrambi i writer producono un trie leggibile, e
  un test verifica che sullo stesso input producano le **stesse firme** (non
  solo che siano entrambi leggibili). 8 test verdi.
- [x] **T31** ✅ **RISOLTO — da 1 firma a 67 168.**
  Causa: il payload della foglia del writer non combaciava con
  `sig_file_loader::read_leaf_payload` in **due** modi.
  1. Ordine dei campi ed endianness: il writer emetteva
     `crc_len:u8, crc16:u16 LE, module_offset:u16 LE`, il decoder legge
     `crc_offset:u16 BE, crc_len:u8, crc:u16 BE`. Stesso numero di byte, campi
     diversi -> CRC decodificati come spazzatura.
  2. **Il difetto fatale:** il writer non emetteva il terminatore `0x00` della
     lista dei nomi extra. Il decoder leggeva quindi il byte di lunghezza-prefisso
     del **nodo successivo** come lunghezza di un nome extra e ne mangiava un
     pezzo, disallineando lo stream. Ogni foglia dopo la prima andava persa.
  Misurato dopo il fix, su scala reale:
  | pattern in | firme lette |
  |---|---|
  | 1 | 1 |
  | 1 000 | 1 000 |
  | 20 000 | 20 000 |
  | **67 168** | **67 168** |
- [x] **T33** ✅ **Causa: non erano senza nome, erano `is_local`.**
  Tutti e 25 965 hanno un nome a offset 0 marcato locale (distruttori, thunk).
  `primary_name()` ora ripiega su un nome locale quando non c'e' un pubblico.
  **Compromesso misurato:** rename 52 -> 240, ma precisione **73.9% -> 64.3%**
  (+1 AGREE, +4 DISAGREE, +183 UNKNOWN). L'oracolo copre solo i simboli
  pubblici, quindi non puo' dirimere se i 188 nuovi siano un guadagno.
  **Decisione aperta:** se la priorita' e' non sbagliare mai un nome, rendere il
  fallback opt-in o a confidenza piu' bassa.
- [x] **T34** ✅ **Causa trovata e knob misurato.** 238/240 rename venivano da
  firme **senza CRC**, 199 con prefisso < 16 byte. Aggiunto
  `set_min_bytes_without_crc(n)` (default 0 = invariato). Curva misurata:
  soglia 16 -> precisione **64.3% -> 88.2%**, falsi positivi 10 -> 2;
  soglia 24 -> 100% ma perde due terzi dei nomi giusti.
  **Decisione ora fondata (iterazione 23):** su 6 binari non-Rust il database
  produce **5 071 falsi positivi a soglia 0** e **0 a soglia 16**. Con la curva
  PDB (16 conserva 15/18 nomi giusti), **si raccomanda 16 come default**: il
  default attuale non e' neutro, e' dannoso. Serve l'ok dell'utente per
  cambiarlo, perche' modifica quali funzioni vengono rinominate.
- [ ] **T35** (crate non mio) `rustre_symbols_pdb::resolve_name_for_address`
  restituisce `None` anche per indirizzi presi dal PDB stesso. Registrato, non
  corretto: appartiene a `rustre-symbols-pdb`.
- [x] **T36** ✅ **Allineato al codec canonico (iterazione 69). Era il QUINTO
  sito sul layout header sbagliato.**
  Misurato: dato un header prodotto dal codec canonico — 61 byte, il formato che
  questo workspace scrive e dichiara di leggere — `IdaSigHeader::parse`
  restituiva **`Truncated`**, perche' pretendeva 88 byte per un campo nome fisso
  di 64 che il layout pubblicato non ha. **Il modulo chiamato `ida_sig_compat`
  era l'unico componente incapace di leggere un header in formato IDA.**
  Ora delega a `rustre_flirt::sig_header`. Rimosse le due costanti che
  codificavano il layout sbagliato (una costante che afferma un'invariante falsa
  e' peggio di nessuna costante) e corretto il doc del modulo, che descriveva
  ancora il campo a 22..86.
  4 test in `tests/ida_compat_reads_the_canonical_header.rs`, inclusi nomi di
  ogni lunghezza (0, 1, 4, 18, 200 byte) e troncamento a ogni offset.
  ⚠️ **Sesta occorrenza dello stesso schema**: il test che lo copriva
  (`ida_sig_header_parse_v9_smoke`) costruiva a mano il layout sbagliato e
  asseriva `cur >= 88`, quindi passava e lo certificava. Riscritto sul codec.
  Riepilogo dei cinque siti: T27 ne corresse due, l'iterazione 43
  `parse_sig_header`, la 45 `load_sig_file`, questa `ida_sig_compat`.
- [ ] **T29** `FlirtPattern` esiste come **due tipi diversi e non collegati** in
  `rustre-flirt` e `rustre-flirt-apply`. `SignaturePack` usa quello di apply.
  Stessa classe di T4/T5/T6, al livello dei tipi.
- [~] **T28** Rigenerare i `.sig` per il runtime del corpus (non solo
  rust-stdlib) — sono le funzioni per cui esistono gia' i 126 prototipi.
  **Indagine fatta (iterazione 56): quale archivio conviene, misurato.**
  Contro `sample1_c.exe`, con l'oracolo del tetto:

  | archivio | firme | trovabili (>=8B) | trovate |
  |---|---|---|---|
  | `libmingw32` | 43 | 24 | **24** (al tetto) |
  | `libmsvcrt` | 364 | 7 | **7** (al tetto) |
  | `libmingwex` | 522 | 1 | 2 |
  | `libucrt` | 68 | 0 | 2 |
  | `libstdc++` (vs C++) | 5427 | 187 | **5** |

  Quindi il runtime davvero collegato nei binari C del corpus e' **libmingw32**
  (piu' una piccola parte di msvcrt), non libmingwex: e' da li' che conviene
  generare. Su entrambi il matcher e' **esattamente al tetto**.
  ⚠️ `libstdc++` e' l'anomalia: 187 trovabili, 5 trovate — e **non e' la scala**
  (riducendo il database alle sole 187, ne trova 3). La lettura coerente e' che
  in C++ i prologhi siano **condivisi** fra molte funzioni distinte, quindi il
  tetto e' lasco su C++ e stretto su C. Non trarne "182 mancate".
  **Fatto (iterazione 57): firme generate e catena misurata end-to-end.**
  `harvest_archives` accettava solo `.rlib`/`.lib` e **non vedeva i `.a`**, cioe'
  tutto il runtime mingw. Aggiunta l'estensione; generate 255 firme da
  libmingw32+libmsvcrt (407 grezze, 26 duplicati esatti, 44 chiavi ambigue).
  Decompilato `sample1_c.exe` con e senza `RUSTRE_SIGDB_DIR`:
  **i 43 file `.c` emessi sono identici** (cambiano solo `elapsed_ms` e
  `out_dir` in summary.json). Traccia di debug:
  `match grezzi 65, dopo resolve 65` e `[flirt→typerecov] considerate 28,
  pubblicate 0, senza prototipo 28`.
  Vedi T17b per il divario dei prototipi, che e' il vero collo di bottiglia.
- [x] **T17c** ✅ **Circolarita' quantificata (iterazione 71): non piu' un
  avvertimento ma un numero.**

  | | conteggio |
  |---|---|
  | nomi in `prototypes.json` | 136 |
  | prototipi pubblicati dal ponte | 227 |
  | **in comune** | **126** |
  | quota della ground truth | **92.6%** |
  | genuinamente indipendenti | **10** |

  Quindi la metrica di arieta' e' tautologica per **piu' di nove nomi su dieci**:
  la sua cifra (122/135) afferma, per quelli, che un file concorda con se stesso.
  I 10 indipendenti sono elencati dal test.
  3 test in `rustre-flirt-apply/tests/arity_metric_is_circular.rs`, uno dei quali
  verifica che la provenance dichiari ancora gli header mingw — se la fonte
  cambiasse, la circolarita' andrebbe rimisurata invece che assunta.
  ⚠️ **Errore di misura mio, corretto prima di pubblicare**: la prima estrazione
  cercava `": "` nel testo e contava **139** nomi dove il file ne ha 136 — un
  errore del 2% nel denominatore del rapporto che l'esempio esiste per
  affermare. Ora usa `serde_json`.
  Metriche portanti restano `behavior.py` (7/14) e `cross_build.py`.
  Vecchia voce: attenzione alla circolarita' prima di misurare.
  `prototypes.json` e i prototipi generati derivano entrambi dagli stessi header
  mingw-w64. Da ora `fidelity_arity.py` **non e' piu' un oracolo indipendente**
  per quei nomi: misurare l'arieta' emessa contro la stessa fonte e'
  tautologico. Metriche portanti: `behavior.py` (7/14) e `cross_build.py`
  (2 incoerenti su 1359). Da fare dopo T17e, non prima: senza match il delta e'
  zero per costruzione.
- [x] **T18** ✅ **Fatto (iterazione 72).**
  `rustre-flirt-apply/examples/flirt_demo.rs` percorre la catena intera —
  archivio -> pattern -> `.sig` -> rilettura -> scansione — e stampa cosa produce
  ogni stadio. Misurato con `libmingw32.a` su un binario C del corpus:
  31 membri -> **43 pattern** (34 con wildcard) -> `.sig` di 3078 byte ->
  **43 firme rilette su 43** -> **24 funzioni identificate** sul target e
  **0** sul binario di controllo.
  **La colonna di controllo e' il punto**: produrre nomi e' facile, il fatto che
  nessuno compaia in un binario Go che quelle funzioni non puo' contenere e'
  l'affermazione che vale. Le due cifre si muovono insieme — all'iterazione 47 il
  controllo ne mostrava 5, dai pattern che il container troncava.
  `crates/rustre-flirt-apply/README.md` documenta la demo e, soprattutto, **come
  leggere i numeri**: il tetto del recall, l'inutilita' dell'auto-riconoscimento
  come misura di valore, e la necessita' di un binario di controllo.
  4 test in `tests/demo_chain_end_to_end.rs`, cosi' la demo non puo' diventare in
  silenzio un programma che stampa numeri.

## Fase 4 — Enterprise polish

- [~] **T19** **Misurato (iterazione 73), non ancora implementato.**
  `missing_docs` non e' attivo in nessuno dei 4 crate. Conteggio degli item
  pubblici senza documentazione:

  | crate | mancanti |
  |---|---|
  | `rustre-flirt` | **275** |
  | `rustre-flirt-gen` | **220** |
  | `rustre-flirt-apply` | **218** |
  | `rustre-analysis-typerecov` | **111** |
  | **totale** | **824** |

  ⚠️ **Trappola di misura**: senza `touch` su `lib.rs` il lint **non gira** e
  `cargo rustc -- -W missing_docs` riporta **0**. La prima misura diceva zero.
  Comando corretto:
  `touch crates/<c>/src/lib.rs && cargo rustc --release -q -p <c> --lib -- -W missing_docs`
  **Da decidere prima di partire**: 824 doc-comment sono lavoro di volume con
  poco valore di verifica. Ha piu' senso attivare `#![warn(missing_docs)]` e
  documentare **solo l'API supportata** — che dipende da T8, dove 30 moduli
  pubblici non hanno alcun uso nel workspace. Documentarli tutti significherebbe
  scrivere 824 commenti di cui buona parte per codice che nessuno chiama.
  Descrizione originale: Doc: `#![warn(missing_docs)]`, doc-test sugli entry point,
  README per crate con il formato `.sig`/`.pat` documentato.
- [ ] **T20** Osservabilità: `tracing` al posto di eventuali `println!`, metriche
  di match (hit rate, collisioni, tempo).
- [ ] **T21** CI: build+test release, clippy -D warnings, fuzz smoke, benchmark
  no-regression gate.
- [ ] **T22** Bug bounty interno: caccia adversariale a bug di correttezza nel
  matching (falsi positivi = funzioni rinominate **male**, il danno peggiore per
  un decompiler: un falso positivo è più dannoso di un match mancato).
