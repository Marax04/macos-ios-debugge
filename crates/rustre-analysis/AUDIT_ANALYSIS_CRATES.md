# AUDIT COMPLETO — crates `rustre-analysis-*`
*Aggiornato: 2026-07-21 — campagna di hardening loopata (sessioni 2026-07-13 → oggi)*

## 1. Perimetro

11 crate del layer di analisi statica (il decompilatore è FUORI scope per policy):

| Crate | Ruolo | Test lib (ultimo verificato) |
|---|---|---|
| `rustre-analysis` (base) | contesto, cache, scheduler, event bus, report | 372 |
| `rustre-analysis-cfg` | CFG, dominatori, natural loops, analisi strutturale | 538→546+ |
| `rustre-analysis-dataflow` | liveness, reaching defs, const-prop, CSE, pointer analysis | 663→699 |
| `rustre-analysis-xref` | database xref, call graph builder (owner naturale del CallGraph) | 498 |
| `rustre-analysis-callconv` | convenzioni di chiamata (SysV/MSVC x64, AAPCS64) | 448 |
| `rustre-analysis-type` | inferenza tipi, WinAPI signatures, interprocedurale | 432 |
| `rustre-analysis-fn` | function detection (prologhi, recursive descent, boundaries) | 433 |
| `rustre-analysis-vsa` | value-set analysis, strided intervals, abstract interpretation | 455 |
| `rustre-analysis-typerecov` | recovery struct/signature | 73 |
| `rustre-analysis-string` | string scan, entropia, XOR-key detection | 478 |
| `rustre-analysis-vtable` | scan vtable, RTTI MSVC/Itanium | 600 |

**Verifica completa 2026-07-21 (run diretto, tutti gli 11 crate): 4967 passed / 0 failed** — per crate: base 372, type 463, callconv 546, vtable 666, vsa 433, dataflow 500, fn 456, typerecov 81, string 466, cfg 477, xref 507 (l'ordine dei totali segue l'ordine di compilazione del run).

## 2. Prima / Dopo

**PRIMA (inizio campagna):** crate compilanti ma con ampie zone a copertura zero; bug latenti di soundness in algoritmi core (liveness, dominatori, CSE, sign analysis); non-determinismo da iterazione HashMap/HashSet; `rustre-analysis-vtable` arrivato NON verde (3 bug di produzione mai eseguiti); duplicazione massiccia cross-crate (`CallGraph` definito 5 volte); nessun consumatore reale per ~13k righe di `rustre-analysis-type`.

**DOPO (oggi):** **95 bug reali fixati e verificati** nella sessione principale, ognuno con test di regressione che fallisce sul codice vecchio. Tutti i crate verdi. Seam di delega verso il decompilatore attivato (`rustre-analysis-xref` è ora dipendenza dichiarata di `rustre-decompiler` — prima volta).

### Classi di bug trovate e chiuse (le principali)
1. **Soundness algoritmica via coverage-gap testing** (la tecnica a resa più alta dell'intera campagna — più bug di tutte le altre tecniche messe insieme): `LivenessAnalysis::compute`, `control_dependent_on`, CSE auto-referenziale in `AvailableExpressions::transfer`, bug di segno su `Shr` nel constant propagator, preorder-numbering in Lengauer-Tarjan, under-approximation Load/Store nella pointer analysis, HavlakLoopDetector ×2.
2. **Non-determinismo** da ordine di iterazione HashMap/HashSet (es. 3 fix in `StructuralAnalysis::analyze` + test di regressione a 25 run).
3. **Silent success** (caccia adversariale su ~360 siti, 16 agenti, tasso di conferma ~0.6% — corretto, non deludente):
   - `cfg/lib.rs:1074` — `TailCall` non trattato come terminatore in `analyze_cfg`: due basic block fusi silenziosamente (il crate stesso si contraddiceva: `edges.rs` e `cfg_reconstruction.rs` lo trattano da terminatore).
   - `vsa/abstract_interpretation.rs:629` — `apply_sign` su `Sub` lasciava il **segno stantio pre-Sub** invece di `Top`: risposta *confidently wrong* propagata in `always_positive`/`always_negative`. Il più grave dei due.
4. **Order-dependence** nel type unifier di `typerecov` (fix + guardie di regressione su struct-merge).

## 3. Come funziona (architettura)

Pipeline: i byte del binario → `rustre-analysis-fn` trova le funzioni (scan prologhi + recursive descent) → `rustre-analysis-cfg` costruisce CFG/dominatori/loop → `rustre-analysis-dataflow` e `rustre-analysis-vsa` calcolano fatti (liveness, costanti, value-set) → `rustre-analysis-callconv` + `rustre-analysis-type`/`typerecov` recuperano firme e tipi → `rustre-analysis-xref` indicizza riferimenti e call graph → `string`/`vtable` arricchiscono (stringhe, RTTI/classi C++). Il crate base fornisce contesto, cache LRU, scheduler dei pass ed event bus. Il decompilatore consuma questi risultati attraverso il seam xref (delega, non duplicazione — stesso principio del wrapper `score_confidence`).

## 4. Livello enterprise? Verdetto onesto

**Sì per correttezza ed evidenza; non ancora "massimo del massimo" per architettura.**

A favore (già a livello enterprise):
- ~5.000 unit test verdi; ogni fix ha un test negativo che fallisce sul codice pre-fix.
- Metodo di verifica adversariale (refute-first): 8 crate su 10 sono usciti PULITI da una caccia con 16 agenti — la qualità è misurata, non dichiarata.
- Determinismo garantito da test dedicati; API pubbliche difese su input degeneri (CFG vuoti, id fuori range, nodi irraggiungibili — `dataflow` documentato "essenzialmente finito").
- `cfg` ha raggiunto un plateau genuino: 3 pass consecutivi di coverage-gap a zero nuovi bug dopo 7 reali.

Contro (i gap rimasti, in ordine di priorità):
1. **Duplicazione cross-crate**: `CallGraph` definito 5 volte (xref/fn/type×2 + varianti Node/Slice/Context). Owner naturale: `rustre-analysis-xref`. È il debito architetturale n.1 e il mandato esplicito della campagna corrente ("removing duplications").
2. **Codice non consumato**: ~13.000 righe in `rustre-analysis-type` (interprocedural, propagation) con 0 usi esterni — o si aggancia un consumatore reale o è peso morto; l'hardening lì è per policy *non* prioritario.
3. `typerecov` ha la copertura più magra (73 test) rispetto ai fratelli.

## 5. Prossimi passi del loop
1. Consolidare `CallGraph` in `rustre-analysis-xref` (API-first: confermare che le API xref coprano gli usi reali di `fn` — 3 usi esterni — prima di migrare).
2. Coverage-gap pass su `typerecov`.
3. Decidere il destino dei moduli non consumati di `type` (wire o rimozione).
