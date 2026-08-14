# rustre-deobf-mba

Crate per la deobfuscazione di espressioni MBA (Mixed Boolean-Arithmetic). Implementa detection, scoring, normalizzazione, riscrittura e semplificazione di espressioni MBA usate come tecnica di offuscamento in binari protetti.

**Dipendenze:** `rustre-deobf`, `serde`

---

## lib.rs — Tipi core e pipeline principale

### `MbaExpr` (enum AST per espressioni MBA)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `mk_add(lhs, rhs)` | `MbaExpr, MbaExpr` | `MbaExpr` | Costruisce nodo Add |
| `mk_sub(lhs, rhs)` | `MbaExpr, MbaExpr` | `MbaExpr` | Costruisce nodo Sub |
| `mk_mul(lhs, rhs)` | `MbaExpr, MbaExpr` | `MbaExpr` | Costruisce nodo Mul |
| `mk_neg(e)` | `MbaExpr` | `MbaExpr` | Costruisce nodo Neg |
| `mk_and(lhs, rhs)` | `MbaExpr, MbaExpr` | `MbaExpr` | Costruisce nodo And |
| `mk_or(lhs, rhs)` | `MbaExpr, MbaExpr` | `MbaExpr` | Costruisce nodo Or |
| `mk_xor(lhs, rhs)` | `MbaExpr, MbaExpr` | `MbaExpr` | Costruisce nodo Xor |
| `mk_not(e)` | `MbaExpr` | `MbaExpr` | Costruisce nodo Not |
| `complexity(&self)` | `&self` | `usize` | Conta i nodi AST (misura complessità) |
| `vars(&self)` | `&self` | `Vec<String>` | Elenca le variabili libere |
| `eval(&self, vars)` | `&self, &HashMap<String,i64>` | `Option<i64>` | Valuta l'espressione su un ambiente |
| `substitute(&self, var, repl)` | `&self, &str, &Self` | `Self` | Sostituisce una variabile con una sottoespressione |
| `is_linear(&self)` | `&self` | `bool` | True se l'espressione è lineare (nessun Mul tra variabili) |
| `parse(s)` | `&str` | `Result<MbaExpr, String>` | Parsing testuale di un'espressione MBA |

### `build_rule_database() -> Vec<SimplificationRule>`

Input: nessuno. Output: `Vec<SimplificationRule>`. Genera il database di regole di semplificazione standard (identità algebriche e booleane).

### `MbaVerifier`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea verificatore con sampling random |
| `verify_equivalent(a, b)` | `&MbaExpr, &MbaExpr` | `VerificationResult` | Verifica equivalenza semantica per sampling |
| `is_always_zero(expr)` | `&MbaExpr` | `bool` | True se l'espressione vale 0 per tutti gli input |
| `is_always_const(expr, c)` | `&MbaExpr, i64` | `bool` | True se l'espressione è costante `c` |
| `find_counterexample(a, b)` | `&MbaExpr, &MbaExpr` | `Option<HashMap<String,i64>>` | Trova un assegnamento che confuta l'equivalenza |

### `MbaSimplifier`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Costruisce simplifier con regole standard |
| `simplify(expr)` | `MbaExpr` | `SimplificationResult` | Semplificazione iterativa bottom-up fino a punto fisso |
| `simplify_once(expr)` | `&MbaExpr` | `(MbaExpr, Vec<String>)` | Singolo passo di riscrittura con log delle regole applicate |
| `apply_rules_bottomup(expr)` | `&MbaExpr` | `(MbaExpr, Vec<String>)` | Applica regole in post-order sull'AST |
| `try_rules(expr)` | `&MbaExpr` | `Option<(MbaExpr, &str)>` | Prova ogni regola e restituisce la prima che si applica |
| `simplify_tree(expr)` | `MbaExpr` | `MbaExpr` | Semplificazione ricorsiva senza tracking delle regole |

### `MbaPatternLibrary`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `standard()` | — | `Self` | Libreria con pattern MBA standard |
| `match_pattern(expr)` | `&MbaExpr` | `Option<&MbaPattern>` | Ritorna il primo pattern che matcha l'espressione |

### `MbaAnalyzer`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea analizzatore |
| `analyze_expression(expr)` | `MbaExpr` | `SimplificationResult` | Analisi completa di una singola espressione |
| `analyze_batch(exprs)` | `Vec<MbaExpr>` | `MbaPassResult` | Analisi in batch di un array di espressioni |

---

## deobf_mba_pass.rs — Passo IR → MBA → IR

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `translate_ir_to_mba(expr)` | `&IrExpr` | `MbaExpr` | Traduce un'espressione IR nel dominio MBA |
| `translate_mba_to_ir(expr)` | `&MbaExpr` | `IrExpr` | Traduce un'espressione MBA semplificata in IR |

### `IrMbaExpr` (wrapper espressione IR con metadati MBA)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `complexity(&self)` | `&self` | `usize` | Complessità dell'espressione IR |
| `is_arithmetic(&self)` | `&self` | `bool` | True se l'espressione è puramente aritmetica |
| `vars(&self)` | `&self` | `Vec<String>` | Variabili libere nell'espressione |

### `PassResult`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `simplification_rate(&self)` | `&self` | `f64` | Frazione di espressioni semplificate |

### `MbaDeobfPass`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea passo con configurazione default |
| `with_config(config)` | `PassConfig` | `Self` | Crea passo con configurazione personalizzata |
| `simplify_expr(expr)` | `&IrExpr` | `(IrExpr, bool)` | Semplifica una singola espressione IR; bool = modificata |
| `apply_pass_to_function(exprs)` | `&[IrExpr]` | `(Vec<IrExpr>, PassResult)` | Applica il passo a tutte le espressioni di una funzione |
| `verify_with_z3(original, simplified)` | `&IrExpr, &IrExpr` | `bool` | Verifica equivalenza via Z3 (fallback se disponibile) |

---

## mba_complexity_scorer.rs — Scoring di complessità

### `TreeMetrics`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `of(expr)` | `&MbaExpr` | `Self` | Calcola metriche strutturali dell'AST (profondità, nodi, foglie) |

### `OpProfile`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `of(expr)` | `&MbaExpr` | `Self` | Profilo degli operatori (conteggio per tipo) |
| `distinct_ops(&self)` | `&self` | `usize` | Numero di tipi di operatori distinti |
| `mixing_ratio(&self)` | `&self` | `f64` | Rapporto operatori booleani/aritmetici |

### `ComplexityScore`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `compute(expr)` | `&MbaExpr` | `Self` | Calcola score di complessità complessivo |
| `is_likely_mba(&self)` | `&self` | `bool` | Euristicamente vero se l'espressione è offuscata MBA |
| `relative_to(other)` | `&Self` | `f64` | Rapporto di complessità relativo a un'altra espressione |

### `MbaComplexityScorer`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea scorer |
| `score(expr)` | `MbaExpr` | `ExprScoringResult` | Assegna score a un'espressione |
| `score_batch(exprs)` | `Vec<MbaExpr>` | `Vec<ExprScoringResult>` | Scoring in batch |
| `score_function(...)` | espressioni funzione | risultati | Scoring per tutte le espressioni di una funzione |
| `filter_mba(exprs)` | `Vec<MbaExpr>` | `Vec<ExprScoringResult>` | Filtra solo le espressioni con alta probabilità MBA |

### Funzioni libere

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `score_function(...)` | espressioni | risultati | Versione standalone dello scoring per funzione |
| `score_histogram(results, bucket_size)` | `&[ExprScoringResult], u32` | `HashMap<u32, usize>` | Istogramma degli score per bucket |

### `FunctionMbaProfile`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `obfuscation_density(&self)` | `&self` | `f64` | Densità di offuscamento: espressioni MBA / totale |

---

## mba_detector.rs — Rilevamento pattern MBA

### `MbaAnalysis`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `analyze(expr)` | `&MbaExpr` | `Self` | Analizza struttura e classifica il tipo di MBA |

### `MbaPatternLibrary`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `default_library()` | — | `Self` | Libreria con pattern MBA predefiniti |
| `match_patterns(expr, depth)` | `&MbaExpr, usize` | `Vec<MbaPattern>` | Tutti i pattern che matchano fino alla profondità indicata |

### `MbaScorer`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea scorer con euristiche default |
| `score(expr)` | `&MbaExpr` | `MbaScore` | Score di offuscamento per una singola espressione |
| `batch_score(exprs)` | `&[MbaExpr]` | `Vec<MbaScore>` | Scoring in batch |
| `top_obfuscated(exprs, n)` | `&[MbaExpr], usize` | `Vec<(&MbaExpr, MbaScore)>` | Le N espressioni con score più alto |

### `MbaStatistics`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `compute(scores)` | `&[MbaScore]` | `Self` | Statistiche aggregate (media, max, distribuzione) |

---

## mba_normalization.rs — Normalizzazione strutturale

### `MbaExprTree` (AST alternativo per normalizzazione)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `add(a, b)` | `Self, Self` | `Self` | Costruisce Add |
| `sub(a, b)` | `Self, Self` | `Self` | Costruisce Sub |
| `mul(a, b)` | `Self, Self` | `Self` | Costruisce Mul |
| `neg(a)` | `Self` | `Self` | Costruisce Neg |
| `and(a, b)` | `Self, Self` | `Self` | Costruisce And |
| `or(a, b)` | `Self, Self` | `Self` | Costruisce Or |
| `xor(a, b)` | `Self, Self` | `Self` | Costruisce Xor |
| `not(a)` | `Self` | `Self` | Costruisce Not |
| `node_count(&self)` | `&self` | `usize` | Numero totale di nodi |
| `depth(&self)` | `&self` | `usize` | Profondità massima dell'albero |
| `vars(&self)` | `&self` | `Vec<String>` | Variabili libere |
| `eval(&self, env)` | `&self, &HashMap<String,i64>` | `Option<i64>` | Valutazione |

### `StructuralSimplifier`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea simplifier con regole strutturali |
| `apply_once(expr)` | `&MbaExprTree` | `Option<(MbaExprTree, &str)>` | Singolo passo strutturale |
| `simplify(expr)` | `MbaExprTree` | `(MbaExprTree, Vec<String>)` | Semplificazione iterativa strutturale |

### `ConstantPropagator`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea propagatore |
| `bind(var, value)` | `impl Into<String>, i64` | — | Lega una variabile a un valore costante |
| `propagate(expr)` | `&MbaExprTree` | `MbaExprTree` | Propaga le costanti nell'albero |

### `NormalFormConverter`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `from_expr(expr)` | `MbaExprTree` | `Self` | Converte in forma normale interna |

### `EquivalenceChecker`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea checker |
| `check_equivalent(a, b, ...)` | espressioni | risultato | Verifica equivalenza strutturale/semantica |
| `is_constant(expr)` | `&MbaExprTree` | `bool` | True se l'espressione è costante |

### `ExprComplexityMetrics`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `compute(expr)` | `&MbaExprTree` | `Self` | Calcola metriche di complessità |
| `complexity_score(&self)` | `&self` | `f64` | Score scalare |

### `MbaNormalizer`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea normalizzatore |
| `bind(var, value)` | `impl Into<String>, i64` | — | Vincola una variabile |
| `normalize(expr)` | `MbaExprTree` | `(NormalForm, bool, Vec<String>)` | Normalizza e riporta se modificata e le regole applicate |
| `complexity_ratio(original, simplified)` | `&MbaExprTree, &MbaExprTree` | `f32` | Rapporto di riduzione della complessità |

---

## mba_oracle.rs — Sintesi e oracle di semplificazione

### Funzioni libere

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `eval(expr, env, mask)` | `&MbaExpr, &HashMap<String,i64>, i64` | `Option<i64>` | Valuta espressione con mask di bit (per aritmetica modulare) |
| `standard_templates()` | — | `Vec<SynthesisTemplate>` | Template di espressioni semplici (basi dell'oracle) |

### `SynthesisTemplate`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `sample(...)` | variabili, campioni | vettore di valori | Campiona il template su input random |
| `matches(candidate)` | `&MbaExpr` | `bool` | True se il candidato ha la stessa truth table del template |

### `MbaOracle`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new(config)` | `OracleConfig` | `Self` | Crea oracle con configurazione |
| `add_template(t)` | `SynthesisTemplate` | — | Aggiunge un template di sintesi |
| `simplify(expr, variables)` | `&MbaExpr, &[String]` | `Option<OracleResult>` | Cerca equivalente semplice tramite matching truth table |
| `simplify_batch(...)` | slice di espressioni | risultati | Batch simplify |
| `confidence_score(result)` | `&OracleResult` | `f32` | Score di confidenza del risultato |

---

## mba_rewriter.rs — Riscrittura basata su regole

### Funzioni libere

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `standard_rewrite_rules()` | — | `Vec<RewriteRule>` | Insieme standard di regole di riscrittura MBA |
| `apply_rewrite(expr)` | `&MbaExpr` | `Option<SimplifiedExpr>` | Tenta di riscrivere con le regole standard |

### `RewriteRule`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new(name, from, to, verifier)` | parametri regola | `Self` | Costruisce una regola di riscrittura |
| `apply(expr)` | `&MbaExpr` | `Option<MbaExpr>` | Applica la regola all'espressione (None se non applicabile) |

### `MbaRewriter`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea rewriter con regole standard |
| `with_rules(rules)` | `Vec<RewriteRule>` | `Self` | Crea rewriter con regole personalizzate |
| `rewrite(expr)` | `MbaExpr` | `RewriteResult` | Riscrittura iterativa fino a punto fisso |
| `single_pass(expr)` | `&MbaExpr` | `(MbaExpr, Vec<RewriteStep>)` | Singolo passo con traccia dei passi applicati |
| `rewrite_cached(expr)` | `MbaExpr` | `MbaExpr` | Riscrittura con cache interna dei risultati |
| `apply_rule(name, expr)` | `&str, &MbaExpr` | `Option<MbaExpr>` | Applica una regola specifica per nome |

---

## mba_simplifier.rs — Simplifier con truth table

### `TruthTable`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `build(expr, var_names)` | `&MbaExpr, &[&str]` | `Self` | Costruisce truth table per le variabili specificate |
| `build_masked(expr, var_names, mask)` | `&MbaExpr, &[&str], i64` | `Self` | Truth table con mask di bit |
| `matches(other)` | `&Self` | `bool` | True se due truth table coincidono (equiv. semantica) |
| `as_u8_key()` | `&self` | `u8` | Chiave compatta a 8 bit per lookup |

### Funzioni libere

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `standard_rules()` | — | `Vec<RewriteRule>` | Regole con verifica tramite truth table |

### `TruthTableVerifier`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `check(a, b)` | `&MbaExpr, &MbaExpr` | `bool` | Verifica equivalenza tramite confronto truth table |

### `MbaExprSimplifier`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea simplifier |
| `simplify(expr)` | `MbaExpr` | `SimplifyResult` | Semplificazione con truth table lookup |
| `apply_rules_once(expr)` | `&MbaExpr` | `(MbaExpr, Vec<String>)` | Singolo passo di riscrittura con log |
| `truth_table_simplify(expr)` | `&MbaExpr` | `Option<MbaExpr>` | Semplificazione diretta per isomorfismo truth table |

---

## mba_simplification.rs — Pipeline di alto livello

### `MbaExprResult`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `from_simplification(original_text, result)` | `String, &SimplificationResult` | `Self` | Costruisce dal risultato di una semplificazione |

### `MbaReport`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `from_results(results)` | `Vec<MbaExprResult>` | `Self` | Aggrega risultati in un report |
| `markdown_summary(&self)` | `&self` | `String` | Genera summary Markdown del report |

### `SimbaSimplifier`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea simplifier stile SiMBA |
| `simplify(expr_text)` | `&str` | `Result<SimbaResult, String>` | Parsing + semplificazione SiMBA |

### `SimplificationResult`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `reduction_ratio(&self)` | `&self` | `f32` | Rapporto di riduzione complessità (0..1) |

### `MbaPipeline`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea pipeline multi-stage |
| `simplify_text(expr_text)` | `&str` | `Result<VerifiedSimplification, String>` | Parsing, semplificazione, verifica di una singola espressione testuale |
| `simplify_batch(expressions)` | `&[&str]` | `MbaReport` | Semplificazione in batch con report aggregato |
| `simplify_and_filter(expressions)` | `&[&str]` | `Vec<VerifiedSimplification>` | Batch filtrando solo i casi effettivamente semplificati |
| `verify_identity(lhs_text, rhs_text)` | `&str, &str` | `Option<bool>` | Verifica se due espressioni testuali sono identiche; None se inconcludente |

### `CachedMbaPipeline`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea pipeline con cache interna |
| `simplify(expr_text)` | `&str` | `Result<&VerifiedSimplification, String>` | Semplifica con memoizzazione |
| `cache_size(&self)` | `&self` | `usize` | Numero di entry in cache |
| `clear_cache(&mut self)` | `&mut self` | — | Svuota la cache |

---

## boolean_algebra_simplifier.rs — Semplificazione booleana pura

### `BoolExpr` (AST booleano)

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `not(e)` | `Self` | `Self` | Costruisce Not |
| `and(l, r)` | `Self, Self` | `Self` | Costruisce And |
| `or(l, r)` | `Self, Self` | `Self` | Costruisce Or |
| `xor(l, r)` | `Self, Self` | `Self` | Costruisce Xor |
| `var(name)` | `impl Into<String>` | `Self` | Costruisce variabile |
| `complexity(&self)` | `&self` | `usize` | Numero di nodi |
| `vars(&self)` | `&self` | `Vec<String>` | Variabili libere |
| `eval(&self, vars)` | `&self, &HashMap<String,bool>` | `Option<bool>` | Valutazione booleana |

### `BoolSimplifier`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea simplifier booleano |
| `simplify(expr)` | `BoolExpr` | `BoolSimplResult` | Semplificazione iterativa con leggi booleane |
| `simplify_once(expr, ...)` | `BoolExpr` | risultato | Singolo passo |

### Funzioni libere

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `convert_to_normal_form(expr, form)` | `BoolExpr, NormalForm` | `BoolExpr` | Converte in NNF/CNF/DNF in base a `form` |
| `to_nnf(expr)` | `BoolExpr` | `BoolExpr` | Trasforma in Negation Normal Form |
| `to_dnf(expr)` | `BoolExpr` | `BoolExpr` | Trasforma in Disjunctive Normal Form |
| `to_cnf(expr)` | `BoolExpr` | `BoolExpr` | Trasforma in Conjunctive Normal Form |
| `bool_exprs_equivalent(a, b)` | `&BoolExpr, &BoolExpr` | `BoolEquivResult` | Verifica equivalenza booleana con risultato dettagliato |
| `bool_exprs_equivalent_strict(a, b)` | `&BoolExpr, &BoolExpr` | `bool` | Verifica equivalenza booleana stretta |

---

## boolean_normalization.rs — CNF/DNF su `MbaExpr`

### `Literal`, `Clause`, `CnfFormula`, `DnfFormula`

| Funzione | Tipo | Descrizione |
|---|---|---|
| `Literal::pos(var)` | costruttore | Letterale positivo |
| `Literal::neg(var)` | costruttore | Letterale negativo |
| `Literal::negate(&self)` | `Literal` | Negazione del letterale |
| `Literal::display(&self)` | `String` | Rappresentazione testuale |
| `Clause::unit(lit)` | costruttore | Clausola unitaria |
| `Clause::is_tautology(&self)` | `bool` | True se la clausola è una tautologia |
| `Clause::display(&self)` | `String` | Testo della clausola |
| `CnfFormula::simplify(&mut self)` | — | Elimina clausole ridondanti |
| `CnfFormula::display(&self)` | `String` | Testo CNF |
| `DnfFormula::display(&self)` | `String` | Testo DNF |
| `DnfFormula::eval(assignment)` | `bool` | Valutazione su assegnamento |
| `DnfFormula::size()` | `usize` | Numero di termini |

### `TruthTableMatrix`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `from_expr(expr, variable_order)` | `&MbaExpr, &[String]` | `Self` | Matrice truth table dall'espressione |

### Funzioni libere

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `to_nnf(expr)` | `MbaExpr` | `MbaExpr` | NNF su MbaExpr (propaga Not verso le foglie) |
| `nnf_to_cnf(expr)` | `&MbaExpr` | `CnfFormula` | Da NNF a CNF |
| `nnf_to_dnf(expr)` | `&MbaExpr` | `DnfFormula` | Da NNF a DNF |
| `split_xor(expr)` | `MbaExpr` | `MbaExpr` | Espande Xor: `a^b → (a|b)&~(a&b)` |
| `balance_and_or(expr)` | `MbaExpr` | `MbaExpr` | Bilancia catene And/Or in alberi bilanciati |

### `BoolNormalizer`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `normalize(expr)` | `MbaExpr` | `(MbaExpr, NormalizationResult)` | Normalizzazione booleana completa con log |

---

## bitwise_arithmetic_folder.rs — Folding costanti e identità bit-a-bit

### Funzioni libere

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `all_fold_rules()` | — | `Vec<FoldRule>` | Tutte le regole di folding (identità, assorbimento, costanti) |

### `BitwiseArithmeticFolder`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea folder con tutte le regole |
| `fold(expr)` | `MbaExpr` | `FoldResult` | Folding iterativo con report |
| `fold_pass(expr)` | `&MbaExpr` | `(MbaExpr, Vec<String>)` | Singolo passo di folding con log |
| `fold_constants_only(expr)` | `MbaExpr` | `MbaExpr` | Solo costant-folding, senza regole identità |

---

## nonlinear_mba_solver.rs — Solver MBA non lineare tramite polinomi

### `Monomial`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `var(name, coeff)` | `impl Into<String>, i64` | `Self` | Monomio di grado 1 con coefficiente |
| `degree(&self)` | `&self` | `u32` | Grado del monomio |
| `eval(&self, vals)` | `&HashMap<String,i64>` | `i64` | Valutazione |
| `monomial_key(&self)` | `&self` | `String` | Chiave canonica per deduplicazione |
| `multiply(other)` | `&Self` | `Self` | Prodotto tra monomi |

### `Polynomial`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `constant(c)` | `i64` | `Self` | Polinomio costante |
| `normalize(self)` | `Self` | `Self` | Raggruppa monomi simili |
| `add(other)` | `Self` | `Self` | Somma polinomiale |
| `sub(other)` | `Self` | `Self` | Differenza polinomiale |
| `mul(other)` | `Self` | `Self` | Prodotto polinomiale |
| `eval(&self, vals)` | `&HashMap<String,i64>` | `i64` | Valutazione |
| `degree(&self)` | `&self` | `u32` | Grado massimo |
| `variables(&self)` | `&self` | `Vec<String>` | Variabili del polinomio |

### `KnownSimplifications`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `standard()` | — | `Self` | Database di semplificazioni polinomiali note |
| `lookup(poly_str)` | `&str` | `Option<&'static str>` | Lookup stringa → espressione semplice equivalente |

### `NonlinearMbaSolver`

| Funzione | Input | Output | Descrizione |
|---|---|---|---|
| `new()` | — | `Self` | Crea solver |
| `mba_to_polynomial(expr)` | `&MbaExpr` | `Polynomial` | Converte un'espressione MBA in rappresentazione polinomiale |
| `reduce_modulo_boolean_axioms(poly)` | `Polynomial` | `Polynomial` | Riduce applicando assiomi booleani (x^2 = x per variabili bit) |
| `groebner_reduce(poly)` | `Polynomial` | `Polynomial` | Riduzione Gröbner-style rispetto a ideal booleano |
| `verify_equivalence_sampling(expr1, expr2)` | `&MbaExpr, &MbaExpr` | `bool` | Verifica campionata dell'equivalenza |
| `refutation_counterexample(...)` | espressioni | controes. | Ricerca controes. per confutare equivalenza |
| `simplify_nonlinear(expr)` | `&MbaExpr` | `SimplificationOutcome` | Pipeline completa: poly → riduzione → lookup → verifica |

---

## Riepilogo per modulo

| Modulo | Classi principali | Funzioni pub totali |
|---|---|---|
| `lib.rs` | `MbaExpr`, `MbaVerifier`, `MbaSimplifier`, `MbaPatternLibrary`, `MbaAnalyzer` | 34 |
| `deobf_mba_pass.rs` | `MbaDeobfPass`, `IrMbaExpr`, `PassResult` | 10 |
| `mba_complexity_scorer.rs` | `MbaComplexityScorer`, `ComplexityScore`, `OpProfile`, `TreeMetrics`, `FunctionMbaProfile` | 14 |
| `mba_detector.rs` | `MbaScorer`, `MbaPatternLibrary`, `MbaAnalysis`, `MbaStatistics` | 9 |
| `mba_normalization.rs` | `MbaExprTree`, `StructuralSimplifier`, `ConstantPropagator`, `EquivalenceChecker`, `MbaNormalizer` | 27 |
| `mba_oracle.rs` | `MbaOracle`, `SynthesisTemplate` | 8 |
| `mba_rewriter.rs` | `MbaRewriter`, `RewriteRule` | 9 |
| `mba_simplifier.rs` | `MbaExprSimplifier`, `TruthTable`, `TruthTableVerifier` | 9 |
| `mba_simplification.rs` | `MbaPipeline`, `CachedMbaPipeline`, `MbaReport`, `SimbaSimplifier` | 14 |
| `boolean_algebra_simplifier.rs` | `BoolExpr`, `BoolSimplifier` | 17 |
| `boolean_normalization.rs` | `BoolNormalizer`, `TruthTableMatrix`, literali/clausole | 17 |
| `bitwise_arithmetic_folder.rs` | `BitwiseArithmeticFolder` | 5 |
| `nonlinear_mba_solver.rs` | `NonlinearMbaSolver`, `Polynomial`, `Monomial`, `KnownSimplifications` | 21 |
| **Totale** | | **194** |
