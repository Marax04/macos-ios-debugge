# rustre-ti-correlate

**Crate:** `rustre-ti-correlate` v0.1.0  
**Dipendenze principali:** `rustre-threatintel`, `rustre-core`, `petgraph`, `serde`, `serde_json`, `anyhow`

Libreria di correlazione threat-intelligence: aggrega IoC, campagne, TTP MITRE ATT&CK, profili attore e sample binari per produrre grafi di correlazione, cluster comportamentali, attribuzioni e timeline temporali.

---

## Funzioni libere (pub fn a livello di modulo)

| Funzione | Modulo | Input | Output | Descrizione |
|----------|--------|-------|--------|-------------|
| `deduplicate_iocs` | `lib` | `Vec<IoC>` | `Vec<IoC>` | Rimuove IoC duplicati per tipo+valore. |
| `correlate_across_sources` | `lib` | `&[&[IoC]]` | `CorrelationResult` | Correla IoC provenienti da più sorgenti, calcola overlap. |
| `cluster_by_campaign` | `lib` | `&[IoC], &[Ttp]` | `Vec<CampaignCluster>` | Raggruppa IoC in cluster di campagna in base a TTP condivisi. |
| `timeline` | `lib` | `&[ThreatEvent], window_secs: u64` | `Vec<TimelineEntry>` | Costruisce una timeline di eventi threat con finestramento temporale. |
| `score_ioc` | `lib` | `&IoC, &CorrelationContext` | `f32` | Assegna uno score di rilevanza a un IoC nel contesto corrente. |
| `build_campaign_timeline` | `campaign_detector` | `&Campaign, &[SampleRecord]` | (timeline struct) | Costruisce la timeline di attività per una campagna. |
| `monthly_pulse` | `campaign_detector` | `&Campaign, &[SampleRecord]` | `Vec<(String, usize)>` | Restituisce il conteggio mensile di sample per campagna. |
| `score_attribution` | `attribution_engine` | `signals, actors` | score | Calcola lo score di attribuzione aggregato dati i segnali. |
| `pearson_correlation` | `temporal_analysis` | `&TimeSeries, &TimeSeries` | `f64` | Coefficiente di correlazione di Pearson tra due serie temporali. |
| `cluster_by_ttps` | `campaign_tracker` | `&[ThreatReport], min_jaccard: f64` | `CampaignTracker` | Raggruppa report in campagne per similarità Jaccard dei TTP. |
| `label_propagation` | `ioc_graph` | `&IocGraph, max_iter: usize` | `HashMap<NodeIndex, usize>` | Algoritmo di label propagation per rilevamento community nel grafo IoC. |
| `build_communities` | `ioc_graph` | `&IocGraph, &HashMap<NodeIndex,usize>` | `Vec<Community>` | Costruisce strutture Community dai label assegnati. |
| `graph_stats` | `ioc_graph` | `&IocGraph` | `GraphStats` | Statistiche aggregate del grafo (nodi, archi, densità). |
| `to_dot` | `ioc_graph` | `&IocGraph` | `String` | Serializza il grafo in formato Graphviz DOT. |
| `tlsh_distance` | `sample_correlator` | `&str, &str` | `Option<u32>` | Distanza TLSH tra due hash fuzzy; None se parse fallisce. |
| `import_jaccard` | `sample_correlator` | `&[String], &[String]` | `f64` | Similarità Jaccard degli import set di due sample. |
| `section_entropy_similarity` | `sample_correlator` | `&[f64], &[f64]` | `f64` | Similarità tra vettori di entropia per sezione. |
| `string_overlap_score` | `sample_correlator` | `&[String], &[String]` | `f64` | Score di overlap per le stringhe estratte di due sample. |
| `correlate_pair` | `sample_correlator` | `SampleDescriptor x2, &CorrelationWeights` | `SampleCorrelation` | Correlazione completa tra due sample (TLSH+imphash+entropy+strings). |
| `cluster_by_imphash` | `sample_correlator` | `&[SampleDescriptor]` | `HashMap<String, Vec<usize>>` | Raggruppa sample per imphash identico. |
| `cluster_samples` | `sample_correlator` | `&DistanceMatrix, threshold: f64` | `Vec<SampleCluster>` | Clustering gerarchico single-linkage sulla matrice delle distanze. |
| `correlate_samples` | `sample_correlator` | `&[SampleDescriptor], &CorrelationWeights` | `(DistanceMatrix, Vec<SampleCluster>)` | Pipeline completa: matrice + cluster per un insieme di sample. |
| `features_from_ioc` | `behavioral_clustering` | `&IoC` | `Vec<BehavioralFeature>` | Estrae feature comportamentali da un IoC per il clustering. |

---

## Metodi pub su struct (per modulo)

### `lib.rs` — `ThreatCorrelator`
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `add_ioc` | `IoC` | `()` | Aggiunge un IoC al correlatore. |
| `add_report` | `ThreatReport` | `()` | Ingerisce un report threat. |
| `correlate_all` | — | `Vec<Correlation>` | Genera tutte le correlazioni disponibili. |
| `find_related` | `&IoC` | `Vec<Correlation>` | Trova correlazioni di un IoC specifico. |
| `cluster_by_family` | — | `HashMap<String,Vec<IoC>>` | Raggruppa IoC per famiglia malware. |
| `high_confidence_correlations` | `min_confidence: u8` | `Vec<Correlation>` | Filtra correlazioni sopra soglia di confidenza. |

### `lib.rs` — `CorrelationGraph`
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `new` | — | `Self` | Crea grafo di correlazione vuoto. |
| `add_correlation` | nodi + relazione | `()` | Aggiunge un arco di correlazione. |
| `find_related` | `&str` | `Vec<String>` | BFS dei nodi raggiungibili da una chiave. |
| `export_dot` | — | `String` | Serializza in DOT. |
| `node_count` / `edge_count` | — | `usize` | Dimensioni del grafo. |

### `lib.rs` — `MitreTechniqueMapper`
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `map_api_to_technique` | `&str` | `Vec<(String,String)>` | Mappa nome API a tecniche MITRE (tactic, technique). |
| `map_apis_to_techniques` | `&[&str]` | `Vec<(String,String)>` | Batch mapping API → MITRE. |
| `classify` | `&[String]` | `String` | Classifica un campione per comportamento prevalente. |
| `score_breakdown` | `&[String]` | `Vec<(String,usize)>` | Breakdown per tattica del punteggio comportamentale. |

### `lib.rs` — `CorrelationResult`
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `filter_by_min_sources` | `min_sources: usize` | `Vec<&IoC>` | IoC presenti in almeno N sorgenti. |
| `max_source_count` | — | `usize` | Massimo numero di sorgenti per un IoC. |

### `lib.rs` — `ThreatEvent`
| Metodo | Input | Output | Descrizione |
|--------|-------|--------|-------------|
| `with_label` | `IoC, timestamp, label` | `Self` | Costruttore con label annotata. |
| `ioc_types` | — | `Vec<&IoCType>` | Tipi di IoC associati all'evento. |

---

### `ioc_graph.rs` — `IocNode` / `IocEdge` / `IocGraph`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `new(kind, value)` | `IocNode` | Crea nodo IoC. |
| `with_confidence`, `with_label` | `IocNode` | Builder. |
| `display_name` | `IocNode` | Nome visualizzabile (label o value). |
| `new(kind)` | `IocEdge` | Crea arco. |
| `weight` | `IocEdge` | Peso inverso alla confidenza (`1-c+0.01`). |
| `get_or_create_node` | `IocGraph` | Upsert nodo per kind+value. |
| `find_node` / `find_node_or_err` | `IocGraph` | Lookup nodo. |
| `add_edge` / `link` | `IocGraph` | Aggiunge arco tra nodi. |
| `neighbors_out` / `neighbors_in` | `IocGraph` | Vicini diretti/inversi. |
| `nodes_of_kind` | `IocGraph` | Filtra per tipo nodo. |
| `shortest_path` | `IocGraph` | Dijkstra su archi pesati. |
| `all_paths` | `IocGraph` | DFS tutti i percorsi fino a `max_depth`. |
| `bfs_distance` | `IocGraph` | Distanza BFS non pesata. |
| `reachable` | `IocGraph` | Set nodi raggiungibili in ≤ N hop. |
| `label_propagation` (free fn) | — | Community detection. |
| `build_communities` (free fn) | — | Costruisce `Vec<Community>` dai label. |
| `graph_stats` (free fn) | — | Statistiche aggregate. |
| `to_dot` (free fn) | — | Export DOT. |

---

### `temporal_correlator.rs` — `TimeCluster` / `EventTimeline` / `TemporalCorrelator`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `duration`, `size`, `is_significant`, `mean_gap_secs` | `TimeCluster` | Metriche del cluster temporale. |
| `events_with_label`, `events_with_ioc` | `TimeCluster` | Filtri su eventi. |
| `ioc_overlap`, `type_overlap` | `TimeCluster` | Jaccard overlap tra cluster. |
| `push`, `sort`, `events`, `len` | `EventTimeline` | Gestione della timeline. |
| `events_in_range`, `events_with_ioc_type` | `EventTimeline` | Query su range/tipo. |
| `start_ts`, `end_ts`, `total_duration` | `EventTimeline` | Estremi temporali. |
| `density_per_hour`, `daily_histogram` | `EventTimeline` | Analisi densità. |
| `new`, `with_config`, `with_gap` | `TemporalCorrelator` | Costruttori. |
| `push`, `ingest` | `TemporalCorrelator` | Inserimento eventi. |
| `cluster` | `TemporalCorrelator` | Esegue clustering temporale a finestra fissa. |
| `pairwise_similarity` | `TemporalCorrelator` | Similarità IoC tra ogni coppia di cluster. |
| `clusters_with_ioc`, `clusters_with_type`, `clusters_with_label` | `TemporalCorrelator` | Query per cluster. |
| `hottest_cluster` | `TemporalCorrelator` | Cluster col maggior numero di eventi. |
| `summary` | `TemporalCorrelator` | `CorrelationSummary` aggregato. |

---

### `temporal_analysis.rs` — `TimeSeries` / `BurstDetector` / `SeasonalAnalyzer` / `CorrelationMatrix`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `observe`, `observe_batch` | `TimeSeries` | Aggiunge timestamp alla serie. |
| `total`, `mean`, `std_dev` | `TimeSeries` | Statistiche aggregate. |
| `sorted_buckets`, `recent_activity` | `TimeSeries` | Accesso ai bucket temporali. |
| `detect` | `BurstDetector` | Individua burst di attività nella serie. |
| `predict_decay` | `IocDecayPredictor` | Predice il tempo di decadimento di un IoC. |
| `autocorrelation` (assoc) | `SeasonalAnalyzer` | Autocorrelazione a lag dato. |
| `analyze` | `SeasonalAnalyzer` | Rileva pattern stagionali. |
| `compute` | `CorrelationMatrix` | Matrice Pearson N×N su più serie. |
| `high_correlation_pairs` | `CorrelationMatrix` | Coppie con correlazione > threshold. |
| `pearson_correlation` (free fn) | — | Correlazione puntuale tra due `TimeSeries`. |

---

### `ttp_analysis.rs` — `TtpEntry` / `TtpCluster` / `TtpGraph` / `TtpTimeline` / `TtpReport` / `TtpAnalyzer`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `effective_id`, `add_evidence` | `TtpEntry` | Accessori e aggiornamento evidenza. |
| `add_ttp`, `tactic_ids`, `avg_confidence` | `TtpCluster` | Gestione cluster di tecniche. |
| `add_node`, `add_edge`, `neighbours`, `predecessors` | `TtpGraph` | Grafo diretto di tecniche. |
| `strongest_pair`, `node_count` | `TtpGraph` | Query sul grafo. |
| `add_event`, `first_event`, `last_event`, `duration_secs`, `window`, `unique_techniques` | `TtpTimeline` | Timeline di eventi TTP. |
| `high_confidence_ttps`, `tactic_coverage_pct` | `TtpReport` | Interrogazione report. |
| `from_apis`, `from_behaviour` (assoc) | `TtpMapper` | Mappa API/keywords a tecniche MITRE. |
| `build_graph` (assoc) | `TtpGraphBuilder` | Costruisce TtpGraph da slice di TtpEntry. |
| `add_from_apis`, `add_from_behaviour`, `record_event`, `cluster_by_tactic`, `build_graph`, `generate_report` | `TtpAnalyzer` | Pipeline completa di analisi TTP. |
| `compare` (assoc) | `TtpComparison` | Differenza di copertura TTP tra due sample. |
| `score`, `classify` | `TtpScorer` | Scoring e classificazione per rischio. |
| `from_entries`, `hottest_tactic`, `count`, `frequency`, `distinct_tactics` | `TacticFrequency` | Frequenza per tattica. |

---

### `attribution_engine.rs` — `ThreatActor` / `Signal` / `AttributionEngine`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `new`, `with_alias`, `with_origin`, `with_ttp`, `with_family`, `with_confidence` | `ThreatActor` | Builder per profilo attore. |
| `from_ttp`, `from_family`, `from_ioc` | `Signal` | Costruttori segnale da oggetti TI. |
| `is_above_threshold`, `label` | `AttributionScore` | Valutazione risultato attribuzione. |
| `register`, `register_all` | `AttributionEngine` | Carica attori nel motore. |
| `score` | `AttributionEngine` | Punteggia lista di segnali contro tutti gli attori. |
| `score_report` | `AttributionEngine` | Attribuzione da ThreatReport completo. |
| `top_n` | `AttributionEngine` | Top-N attori più probabili. |
| `get_actor`, `get_actor_or_err` | `AttributionEngine` | Lookup attore per ID. |
| `score_or_err` | `AttributionEngine` | Versione Result<> di score. |
| `score_attribution` (free fn) | — | Scoring standalone senza engine. |

---

### `actor_tracker.rs` — `TtpMapping` / `ActorProfile` / `ActorTracker`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `new`, `add_evidence` | `TtpMapping` | Mapping TTP con evidenza. |
| `add_campaign`, `add_ttp`, `add_ioc`, `update_timestamps` | `ActorProfile` | Aggiornamento profilo attore. |
| `tactics`, `technique_count`, `technique_overlap` | `ActorProfile` | Query profilo. |
| `register_actor`, `ingest_report` | `ActorTracker` | Carica profili e report. |
| `profile`, `all_profiles` | `ActorTracker` | Recupero profili. |
| `actor_for_campaign` | `ActorTracker` | Mappa campagna → attore. |
| `compute_campaign_links` | `ActorTracker` | Calcola link tra campagne condivise da stessi attori. |
| `attribute_ioc` | `ActorTracker` | Attribuisce un IoC all'attore più probabile con confidenza. |
| `find_by_techniques` | `ActorTracker` | Attori ordinati per numero di tecniche in comune. |

---

### `actor_attribution.rs` — `AttributionResult` / `AttributionEngine`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `add_evidence`, `add_alternative`, `recompute_confidence`, `evidence_kinds` | `AttributionResult` | Gestione risultato attribuzione. |
| `register_actor_ioc`, `register_actor_family` | `AttributionEngine` | Registra associazioni IoC/famiglia per attore. |
| `attribute` | `AttributionEngine` | Attribuisce lista IoC a un attore (`Option`). |
| `attribute_or_err` | `AttributionEngine` | Versione `Result`. |
| `attribute_from_report` | `AttributionEngine` | Attribuzione da ThreatReport. |
| `known_actors` | `AttributionEngine` | Lista attori registrati. |

---

### `attribution.rs` — `AttributionEvidence` / `ThreatActor` / `AttributionEngine`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `new`, `with_artefact` | `AttributionEvidence` | Crea evidenza con kind, descrizione, peso. |
| `has_ttp`, `uses_malware`, `matches_name` | `ThreatActor` | Predicati sul profilo attore. |
| `from_evidence`, `strongest_evidence` | `AttributionResult` | Costruzione e query risultato. |
| `actors`, `find_actor` | `AttributionEngine` | Accesso agli attori. |
| `attribute` | `AttributionEngine` | Attribuzione completa con evidenza. |
| `attribute_by_ttps`, `attribute_by_family` | `AttributionEngine` | Attribuzioni specializzate. |
| `actors_by_country` | `AttributionEngine` | Filtra attori per paese di origine. |

---

### `ioc_correlator.rs` — `CorrelationScore` / `IocMatch` / `MultiSourceResult` / `IocCorrelator`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `compute(structural, source_overlap, co_occurrence, temporal)` | `CorrelationScore` | Score composito pesato su 4 dimensioni. |
| `as_percent`, `meets_threshold` | `CorrelationScore` | Conversione e confronto. |
| `shared_sources`, `is_significant` | `IocMatch` | Sorgenti condivise e soglia significatività. |
| `above_threshold`, `sorted_by_score`, `top_n`, `filter_by_min_sources` | `MultiSourceResult` | Query sui risultati multi-sorgente. |
| `add_source`, `correlate` | `IocCorrelator` | Pipeline di correlazione multi-sorgente. |
| `lookup`, `source_name` | `IocCorrelator` | Accesso a IoC per tipo/valore e sorgente. |

---

### `campaign_correlation.rs` — `CampaignLink` / `CampaignCorrelator`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `new`, `contribution` | `CampaignOverlap` | Overlap tra campagne con peso. |
| `from_overlaps`, `overlap_categories`, `total_shared_items` | `CampaignLink` | Link aggregato tra campagne. |
| `add_report`, `correlate_all` | `CampaignCorrelator` | Ingestione report e correlazione. |
| `significant_links`, `links_for_campaign` | `CampaignCorrelator` | Filtra link rilevanti. |
| `link_map`, `most_connected_campaign` | `CampaignCorrelator` | Vista mappa e hub. |
| `ioc_jaccard` | `CampaignCorrelator` | Jaccard IoC tra due campagne specifiche. |

---

### `campaign_analysis.rs` — `CampaignCluster` / `CampaignAnalyzer` / `CampaignReport`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `new`, `add_indicator`, `add_ttp`, `add_actor`, `tag` | `CampaignCluster` | Costruzione cluster campagna. |
| `shares_ttp`, `shares_actor` | `CampaignCluster` | Test di sovrapposizione. |
| `compute` | `TtpSimilarity` | Similarità TTP tra due cluster. |
| `is_significant` | `TtpSimilarity` | Sopra soglia. |
| `compute` | `TemporalCorrelation` | Correlazione temporale tra cluster. |
| `add_cluster`, `compute_ttp_similarities`, `compute_temporal_correlations` | `CampaignAnalyzer` | Pipeline di analisi. |
| `related_cluster_pairs`, `generate_report` | `CampaignAnalyzer` | Coppie correlate e report finale. |
| `to_markdown`, `to_json` | `CampaignReport` | Serializzazione report. |

---

### `campaign_tracker.rs` — `Campaign` / `CampaignTracker`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `new`, `with_description` | `CampaignDef` | Definizione campagna. |
| `add_member`, `add_link`, `add_ttps`, `add_ttp_objects` | `Campaign` | Popola campagna con report e TTP. |
| `size`, `ttp_jaccard`, `display_name` | `Campaign` | Metriche campagna. |
| `with_min_ttp_similarity`, `with_min_link_confidence` | `CampaignTracker` | Config soglie. |
| `add_link`, `campaigns`, `campaign_for_report` | `CampaignTracker` | Gestione tracker. |
| `summary` | `CampaignTracker` | Stringa di riepilogo. |
| `cluster_by_ttps` (free fn) | — | Costruisce CampaignTracker da report per Jaccard TTP. |

---

### `campaign_detector.rs` — `CampaignDetector`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `new`, `with_defaults` | `CampaignDetector` | Costruttori. |
| `detect` | `CampaignDetector` | Rileva campagne da slice di `SampleRecord`. |
| `build_campaign_timeline` (free fn) | — | Timeline attività per campagna. |
| `monthly_pulse` (free fn) | — | Conteggio mensile sample per campagna. |

---

### `graph_correlator.rs` — `IoCGraph` / `IoCGraphBuilder`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `new`, `add_node`, `get_node`, `get_node_by_value`, `node_count` | `IoCGraph` | Gestione nodi. |
| `add_edge`, `get_edge`, `edge_count`, `out_edges`, `in_edges` | `IoCGraph` | Gestione archi. |
| `pivot` | `IoCGraph` | Pivot su un nodo: restituisce nodi collegati per tipo. |
| `shortest_path` | `IoCGraph` | Percorso minimo BFS per valore. |
| `detect_communities` | `IoCGraph` | Label propagation per community. |
| `community_members`, `community_summary` | `IoCGraph` | Query community. |
| `add_pdns`, `add_co_observation`, `add_c2_communication`, `add_attribution` | `IoCGraphBuilder` | Builder per relazioni tipizzate. |
| `build` | `IoCGraphBuilder` | Finalizza il grafo. |

---

### `clustering.rs` — `SimilarityMatrix` / `IocCluster` / `IocClusterer`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `from_feature_sets` | `SimilarityMatrix` | Costruisce matrice Jaccard da feature set. |
| `similarity`, `pairs_above` | `SimilarityMatrix` | Query similarità. |
| `new`, `is_noise`, `all_features` | `IocCluster` | Cluster di IoC. |
| `add_ioc`, `add_sample`, `add_features` | `IocClusterer` | Inserimento elementi. |
| `similarity_matrix`, `cluster` | `IocClusterer` | Esecuzione clustering. |
| `cluster_by_infrastructure` | `IocClusterer` | Clustering specializzato per infrastruttura. |
| `merge_clusters` (assoc) | `IocClusterer` | Unisce cluster a bassa distanza. |

---

### `behavioral_clustering.rs` — `BehavioralProfile` / `Cluster` / `BehavioralClusterer`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `features_from_ioc` (free fn) | — | Estrae feature comportamentali da IoC. |
| `from_ioc` | `BehavioralProfile` | Profilo comportamentale da IoC. |
| `similarity`, `shares_features` | `BehavioralProfile` | Confronto tra profili. |
| `new`, `add`, `recompute_centroid`, `cohesion` | `Cluster` | Gestione cluster k-means like. |
| `cluster`, `assign` | `BehavioralClusterer` | Pipeline di clustering. |
| `clusters`, `largest_cluster`, `cluster_iocs` | `BehavioralClusterer` | Accesso e utility. |
| `profiles_in_cluster`, `merge_clusters`, `split_cluster`, `top_k_by_cohesion` | `BehavioralClusterer` | Operazioni avanzate su cluster. |

---

### `sample_correlator.rs` — `SampleDescriptor` / `DistanceMatrix` / `SampleCluster`
| Metodo | Struct | Descrizione |
|--------|--------|-------------|
| `import_set`, `string_set` | `SampleDescriptor` | Set per calcolo Jaccard. |
| `compute(samples, weights)` | `DistanceMatrix` | Matrice distanze N×N con pesi configurabili. |
| `get`, `nearest_neighbors`, `similar_pairs`, `len` | `DistanceMatrix` | Accesso e query. |

---

## Conteggio funzioni pubbliche

| Categoria | Conteggio approssimativo |
|-----------|--------------------------|
| Funzioni libere (`pub fn`) | 23 |
| Metodi `pub fn` su struct | ~260 |
| **Totale** | **~283** |
