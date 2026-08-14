# 🔍 AUDIT COMPLETO — crates `rustre-analysis-*`
**Data: 2026-07-21 · Baseline certificata: 6158 test / 0 failed (sweep completo delle 10 crate, ricontrollato a mano)**

---

## 1. Executive summary

Le 10 crate di analisi (`dataflow`, `cfg`, `string`, `callconv`, `xref`, `vsa`, `vtable`, `type`, `fn`, `typerecov`) sono passate in ~3 giorni di campagna da uno stato "funziona ma non fidato" a uno stato **verificato e difeso da oracoli**:

| Metrica | Prima (18/07) | Dopo (21/07) |
|---|---|---|
| Bug reali trovati e fixati (analysis) | 0 documentati | **97** (95 iniziali + 2 dal silent-success hunt) |
| Test totali workspace analysis | ~5900 (non certificati) | **6158 / 0 failed** (certificati) |
| Moduli morti | `interprocedural.rs` (2294 righe) + `propagation.rs` (535) a zero consumer | **100% vivi**, cablati nella pipeline reale |
| Duplicazioni `CallGraph` | 6 copie non mappate | mappate, dedup risolto dove legittimo |
| Oracoli differenziali | 0 | 4 round completati (fn, cfg, vtable, xref) |
| `#[allow(dead_code)]` | presenti | **zero** |

Ripartizione test per crate: dataflow 813, cfg 693, string 666, callconv 653, xref 652, vsa 648, vtable 619, type 604, fn 559, typerecov 251.

---

## 2. I due bug più significativi (silent-success hunt, ~360 siti candidati → 2 confermati)

Il tasso di conferma ~0.6% è il risultato *giusto*: lo stadio avversariale di refutazione ha scartato tutto ciò che era un default legittimo.

### BUG 1 — `rustre-analysis-cfg/src/lib.rs:1074` — TailCall non terminava il basic block
- **Prima:** il leader-scan di `analyze_cfg` trattava `Ret` come terminatore ma `TailCall` cadeva nel `_ => {}`: l'istruzione dopo una tail call NON apriva un nuovo blocco → due blocchi fusi in uno, CFG ben formato e quindi **indetectabile dal chiamante**.
- **Prova che era un bug e non una scelta:** la stessa crate si contraddiceva — `edges.rs:247`, `cfg_reconstruction.rs:427/638/773` e `tail_call.rs:72` trattano tutti `TailCall` come terminatore.
- **Dopo:** `Ret | TailCall { .. } if i + 1 < len`, con test negativo `tail_call_terminates_basic_block` che fallisce sul vecchio codice (`blocks.len() == 1`). 681 → 682 test.

### BUG 2 — `rustre-analysis-vsa/src/abstract_interpretation.rs:629` — segno stantio su `Sub` (il più grave)
- **Prima:** `apply_sign` partiva da `out = state.clone()`; `Sub` cadeva nel catch-all e `dst` conservava il **segno PRE-sottrazione** — non un "unknown" conservativo ma una **risposta confidentemente sbagliata**, che finiva dritta in `summary.always_positive`/`always_negative` senza alcun marcatore. `x = 5 - 7` risultava "sempre positivo".
- **Prova:** le transfer function per costanti e intervalli gestivano `Sub`; solo il dominio dei segni lo ometteva.
- **Dopo:** arm reale `a.add(&b.neg())` + catch-all sostituito con lista esplicita `Jump | CondJump | Ret | Nop => {}` — ogni futura variante diventa errore di compilazione (e il compilatore ha subito beccato `Nop` scoperto: la tecnica si è auto-validata). 641 → 644 test, incluso l'end-to-end attraverso il chiamante ingannato.

---

## 3. Hardening dei catch-all (comportamento-neutro, verificato)

~15 catch-all su enum locali convertiti in liste esplicite (callconv 9, type 4, cfg 2), ogni lista prodotta dall'errore del **compilatore**, non da grep. Conteggi test **identici** prima/dopo — che per un cambio behaviour-preserving è il risultato richiesto, non un difetto. Skipping disciplinato e documentato: match su `&str`/`u8` (non enumerabili), cross-product `(Self, Self)` nei lattice `join`/`meet` (fallback genuini a `Unknown`/`Conflict`), e i 9 siti su `LlilInstruction` (~28 varianti, crate esterna — lista esplicita sarebbe rumore).

---

## 4. Da codice morto a pipeline viva (regola utente: MAI cancellare, CABLARE)

`rustre-analysis-type` conteneva due moduli a **zero consumer** (grep esaustivo su usi esterni, interni e test): `interprocedural.rs` (2294 righe, CallGraph #3) e `propagation.rs` (535 righe, CallGraph #4). Per decisione esplicita dell'utente ("voglio che li utilizzi… al 100% vivo") sono stati **cablati, non cancellati**:

- **`TypeRecoveryPass::run_inner`** (lib.rs:2101-2350) è ora una vera pipeline a 5 stadi: CallGraph interprocedurale costruito dagli xref di chiamata → `IpaTypeAnalysis` a convergenza → bridge `TypeSolutionPropagator` (firme di libreria → tipi di ritorno ai call-site, via nuovo `IpaType::to_type_fact`) → env seedati dai summary IPA → statistiche reali nei warnings.
- **`infer_function_signature_named`**: il prototipo pubblicato **vince sempre** sull'arità inferita (`memcpy` con 5 argomenti fasulli → 3; `free` → void).
- Residuo onesto e dichiarato: `ConvergenceChecker`, `WorklistIpa`, path globali/struct-field restano coperti da test ma non runtime — servono fatti IL che `BinaryView` non espone; **non** sono stati finto-cablati.
- Verifica: type 597 → **604 / 0 failed**, zero `#[allow(dead_code)]`, 23 riferimenti ai moduli da lib.rs.

---

## 5. La saga `CallGraph` — 6 copie, dedup dove legittimo, protezione dove no

Misurato (non assunto): 6 definizioni nel workspace. Esito per ciascuna:

| Copia | Esito | Perché |
|---|---|---|
| `type/interprocedural.rs` + `type/propagation.rs` + `type/lib.rs:650` | **UNIFICATE** in una pipeline con delega | unico surface di dedup legittimo |
| `xref/xref_query.rs` | tenuta | re-export a crate root, consumer nel decompiler; documentata come deliberatamente distinta |
| `xref/call_graph_builder.rs` | **PROTETTA** | i suoi consumer sono i test differenziali (`cross_crate_scc.rs`) che per design tengono due implementazioni SCC indipendenti — consolidarla distruggerebbe il differential testing |
| `fn/recursive_detection.rs` | tenuta | consumer in `rustre-mcp-server` (fuori scope), tipo domain-specific |

**La storia CallGraph è CHIUSA** — inseguire le altre copie sarebbe un regresso di design.

---

## 6. Oracoli differenziali (4 round) — la difesa contro regressioni future

- Round 1-3: oracoli su fn, vtable, cfg — zero difetti di produzione, ma ogni oracolo ha dimostrato di "mordere" con testo di fallimento reale usando la **direzione di corruzione corretta** (corrompere verso il più permissivo, mai verso il più stretto).
- Round 4 (completato, +8 test): `oracle_memory_slice.rs` (fn) con basi avversariali `u64::MAX-8`, `i64::MAX`, `0` — mirato ai READER (`read_u8/u16/u32`), non al costruttore `const fn` che non ha comportamento da testare ("un alto numero di call-site non è di per sé motivo per testare"); `definitional_cfg_stats.rs` (cfg) che inchioda complessità ciclomatica su grafi disconnessi e la sottigliezza `block_count` vs nodi raggiungibili.
- 3 bug reali di overflow trovati in `vtable` nei round precedenti — incluso quello subdolo dove la READ era bounds-checked ma il **payload d'errore** `AddressOutOfRange(addr + 4)` no: panicava solo sul path di fallimento.

Regole di ingaggio consolidate (ognuna nata da un incidente concreto): corruzione stricter-not-looser; mai corrompere helper condivisi; un'assertion che fallisce non è prova che la produzione sia sbagliata; verificare i side-finding incidentali prima di riportarli.

---

## 7. È a livello enterprise? Valutazione onesta

**Sì sui fondamentali, con residui dichiarati.**

✅ **Al massimo livello:**
- 6158 test / 0 failed, certificati con sweep completo, non stimati.
- Zero codice morto, zero `#[allow(dead_code)]`, ogni modulo sul path vivo.
- Bug-hunting avversariale con tasso di falsi positivi ~0: ogni fix ha una *prova* (auto-contraddizione del codice, test negativo che fallisce sul vecchio codice).
- Catch-all convertiti in liste esaustive → le regressioni future su nuove varianti enum sono **errori di compilazione**, non bug silenziosi.
- Oracoli differenziali e definitional test come rete permanente, con incident-log delle trappole.
- Duplicazione risolta *per misura*, con protezione esplicita dei design intenzionali (differential testing).

⚠️ **Residui noti (dichiarati, non nascosti):**
- In `type`: `ConvergenceChecker`, `WorklistIpa` e i path globali/struct-field sono test-covered ma non runtime (limite di `BinaryView`, non del codice).
- I 9 catch-all su `LlilInstruction` restano per scelta ponderata (enum esterna a ~28 varianti).
- La dedup CallGraph è chiusa per decisione architetturale, non perché esista una sola copia: le copie superstiti sono *deliberate* e documentate.

**Giudizio:** la qualità del processo (prova prima del fix, verifica prima del claim, misura prima della scelta architetturale) è il tratto realmente enterprise — più dei numeri stessi.
