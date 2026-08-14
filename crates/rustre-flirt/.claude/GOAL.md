# GOAL — FLIRT stack + type recovery, enterprise-grade

**Obiettivo unico e misurabile:** portare **4 crate** a livello enterprise —
`rustre-flirt`, `rustre-flirt-gen`, `rustre-flirt-apply` e
`rustre-analysis-typerecov` — corretti, senza duplicazione interna, senza panic
path raggiungibili da input non fidato, con audit di sicurezza e benchmark, e
con una demo end-to-end che prova il valore verso il decompiler.

## ⚠️ Il presupposto che si è rivelato falso (misurato 2026-07-28)

La tesi di partenza era: «FLIRT alimenta `rustre-analysis-typerecov`, quindi è un
moltiplicatore diretto». **Quel collegamento non esiste.**
`rustre-analysis-typerecov` non dipende da nessuno dei tre crate FLIRT
(`Cargo.toml`: solo `rustre-analysis`, `rustre-analysis-type`, `thiserror`,
`serde`, `iced-x86`) e nel suo sorgente **non compare mai** la stringa `flirt`.

Il "Level 7 — signature da FLIRT" della type recovery multilivello oggi **non è
implementato**. Il moltiplicatore non è basso: è **zero**, perché il filo non è
collegato. Questo rende **T17 il task di maggior valore dell'intero progetto**,
non un'ottimizzazione finale.

## Definition of Done (tutte, non a scelta)

| # | Criterio | Baseline 2026-07-28 | Target |
|---|---|---|---|
| D1 | `cargo test --release` sui 3 crate | 362/363 (1 FAIL) | 100% verde |
| D2 | `cargo clippy --release -- -D warnings` | non misurato | 0 warning |
| D3 | Implementazioni CRC16 duplicate | 7+ | 1 canonica in `rustre-flirt` |
| D4 | Duplicazione | "~12 moduli" era sbagliato: **3** moduli paralleli (2 morti, 935 righe) ma **52 tipi pubblici duplicati** | ridurre i 52; i tipi contano piu' dei moduli |
| D5 ✅ | `unwrap/expect/panic!` in src su path di parsing | "416" contava il codice di test | **50 in produzione**, 0 raggiungibili da input non fidato (verificato con sweep ostile) |
| D6 | Fuzz/property test su parser `.pat`/`.sig` | 0 | ≥3 target, 0 crash |
| D7 | Round-trip gen→sig→apply su corpus reale | non esiste | harness `flirt_e2e` verde |
| D8 | Demo: nomi FLIRT propagati nel corpus decompiler | non esiste | report numerico prima/dopo |
| D9 ✅ | Benchmark scan | non esisteva | **103 ms** build 67k firme, **149-235 MB/s** scan; gate a 4 test |
| D10 ✅ | Audit sicurezza (OOB, integer overflow, archive bomb, `unsafe`) | "3 `unsafe`" era un falso positivo del grep | **0 `unsafe`**, `#![forbid(unsafe_code)]` su tutti e 4 |
| D11 | `typerecov`: test release | 282 verdi | resta verde, + oracle su corpus reale |
| D12 | `typerecov`: clippy `-D warnings` | **205 warning** | 0 |
| D13 | **Level 7 collegato**: `typerecov` consuma i match FLIRT | **inesistente** | implementato + delta misurato su corpus |

## Baseline dei 4 crate (misurata 2026-07-28)

| Crate | LOC | test verdi | clippy | `unsafe` | `unwrap/expect/panic` |
|---|---|---|---|---|---|
| rustre-flirt | 17 195 | — | — | 0 | 76 |
| rustre-flirt-gen | 18 376 | — | — | 0 | 164 |
| rustre-flirt-apply | 20 109 | — | — | 3 | 176 |
| *(i 3 FLIRT insieme)* | 55 680 | **1662** | 135 | 3 | 416 |
| rustre-analysis-typerecov | 7 801 | **282** | **205** | **0** | 55 |

Nota su `typerecov`: è il crate più piccolo e con la cultura di test migliore —
ha già oracle veri (`live_surface_oracle.rs`, `partition_oracle.rs`,
`logic_regressions.rs`), non solo unit test. Ma ha **più warning clippy dei tre
crate FLIRT messi insieme** (205 contro 135) su un settimo delle righe.

## Regole operative (non negoziabili)

- **SEMPRE release**: `cargo build --release` / `cargo test --release`. Mai debug.
- Un cambiamento alla volta → test → build release → misura → aggiorna
  `PROGRESS.md`. Niente refactor a tappeto non verificati.
- Nessun numero pubblicato senza averlo misurato in questa sessione.
- Ogni fix di un bug porta con sé il test che lo avrebbe intercettato.
