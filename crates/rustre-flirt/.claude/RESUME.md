# RIPARTENZA — leggi questo per primo

Ultimo aggiornamento: **2026-07-31**, fine sessione 3 (iterazioni 47→73).

## 1. Riarmare il loop (NON sopravvive alla chiusura della sessione)

Il job cron vive solo nella memoria della sessione: chiudendo Claude **sparisce**.
Va ricreato. Basta che l'utente scriva `/loop` con questo prompt, oppure che
l'assistente invochi la skill `loop` con `60s` + il testo qui sotto:

```
Lavora sull'obiettivo enterprise dei 4 crate: rustre-flirt, rustre-flirt-gen,
rustre-flirt-apply e rustre-analysis-typerecov. Ad ogni iterazione: (1) leggi
C:\Users\Fra\Desktop\RustRE\crates\rustre-flirt\.claude\GOAL.md, TODO.md e
PROGRESS.md; (2) prendi il primo task non completato in ordine di priorita;
(3) implementalo con il test che lo verifica; (4) SEMPRE cargo build --release e
cargo test --release -p rustre-flirt -p rustre-flirt-gen -p rustre-flirt-apply
-p rustre-analysis-typerecov, mai debug; (5) se tutto e verde aggiorna TODO.md
(spunta il task) e PROGRESS.md con i numeri MISURATI in questa iterazione, e
salva in memoria ogni scoperta durevole; se rosso, ripara prima di passare oltre.
Un task alla volta, niente refactor a tappeto non verificati. Non pubblicare mai
un numero non misurato.
```

## 2. Da dove ripartire

Nessuna verifica pendente: l'ultima iterazione (73) ha solo **misurato** T19 e
non ha toccato codice. Il primo task aperto in ordine di priorita' e' **T19**,
ma leggi prima la nota li' sotto: dipende da una decisione su T8.

Sequenza standard di ogni iterazione:

```bash
cargo build --release -p rustre-flirt -p rustre-flirt-gen -p rustre-flirt-apply -p rustre-analysis-typerecov
# poi i test UN CRATE ALLA VOLTA (vedi punto 3)
cargo run --release -q -p rustre-flirt-apply --example self_match_experiment   # neutralita'
```

Solo dopo un verde vero si spunta un task in `TODO.md`.

## 3. Contare i test — il comando giusto, non a occhio

Due errori pagati nella sessione 2: un totale sommato a mente, e un "0 falliti"
che non contava affatto i fallimenti. Usare sempre:

```bash
cargo test --release --no-fail-fast -p rustre-flirt -p rustre-flirt-gen \
  -p rustre-flirt-apply -p rustre-analysis-typerecov 2>&1 | tee /tmp/t.log \
  | grep -oE "[0-9]+ (passed|failed)" | awk '{s[$2]+=$1} END {for (k in s) print k"="s[k]}'
grep -c '^test result: FAILED' /tmp/t.log   # deve essere 0
```

`--no-fail-fast` e' obbligatorio: senza, cargo interrompe i target rimanenti al
primo rosso e il totale e' troncato.

## 4. Stato misurato a fine sessione 3 (iterazioni 47→73)

| metrica | valore | quando |
|---|---|---|
| test verdi (4 crate, release) | **2212**, 0 falliti | iter. 72 |
| auto-riconoscimento con CRC (`libz.a`) | **97.0%** — pari alla baseline senza CRC | iter. 54 |
| auto-riconoscimento, senza wildcard | **100.0%** | iter. 54 |
| falsi positivi cross-binario | **0** (erano 5) | iter. 53 |
| falsi positivi rust-stdlib su 6 binari estranei | **0** (erano 5071) | iter. 53 |
| demo end-to-end (`libmingw32.a`) | 24 nomi sul target, **0** sul controllo | iter. 72 |
| moduli pubblici senza alcun uso | **30** su 70 | iter. 62 |
| costrutti che possono panicare (produzione) | **59**, con gate | iter. 66 |
| clippy in produzione | flirt 5, gen 3, apply 10, typerecov 14 | iter. 67-68 |
| item pubblici senza doc | **824** | iter. 73 |
| circolarita' della metrica di arieta' | **92.6%** della ground truth | iter. 71 |

### Le tre correzioni che hanno spostato i numeri

1. **Il container `.sig` scartava i wildcard** (iter. 53): troncava al primo
   wildcard, quindi 16 byte diventavano 3. Ora il leaf porta una coda mascherata
   (ctrl `0x02`); i file vecchi restano leggibili.
2. **La finestra CRC non era contigua** (iter. 54): il generatore saltava i byte
   mascherati, lo scanner ne leggeva N contigui — `crc_len` aveva due
   significati. Ora la finestra si ferma al primo byte mascherato.
3. **Cinque componenti implementavano il layout header IDASGN** ognuno a modo
   suo (iter. 43, 45, 69). Tutti delegano a `rustre_flirt::sig_header`.

## 5. Le cose da non dimenticare

1. **Ogni numero di questo repo va misurato con due filtri**: escludere i test
   (per profondita' di graffe, non tagliando al primo `#[cfg(test)]`) e
   filtrare per percorso del crate. Numeri gonfiati trovati: clippy 197→14 e
   106→18, unwrap 55→9, moduli morti 52→30, ground truth 139→136.
2. **Un lint che riporta 0 va sospettato**: senza `touch` su `lib.rs` non gira
   affatto (missing_docs riportava 0 dove erano 111).
3. **`cargo test` va lanciato per crate**: la run unica supera i 590 s per
   contesa sul lock, e un totale da una run troncata non e' un totale.
4. **Ogni misura di riconoscimento vuole un binario di controllo.** Il recall va
   misurato contro cio' che il target **contiene** (`recall_ceiling`), non
   contro il numero di firme.
5. **I test su formati binari costruiscono i byte col codec canonico**, mai a
   mano: sei volte un test scritto a mano ha certificato il layout sbagliato che
   il parser leggeva.

## 6. Cinque decisioni aperte — dell'utente, non da prendere da soli

1. **Soglia 16 come default.** Due corpora indipendenti concordano: rust-stdlib
   (5071 falsi positivi a 0, zero a 16) e mingwex cross-binario (8 basta, 16 non
   costa nulla, 24 distrugge l'unico match vero).
2. **Cancellare 935 righe morte** (`flirt_matcher_v2` 786 + `signature_matcher_new`
   149). Sono `pub`: e' un breaking change.
3. **Quale convenzione per `crc_offset`**: `scan_fast` lo legge RELATIVO alla fine
   del pattern, `Disambiguator::check_crc` e i produttori in `ida_sig_compat` come
   ASSOLUTO. Ogni convenzione ha i suoi test verdi, quindi sceglierne una rompe
   gli altri.
4. **I 30 moduli pubblici senza alcun uso** (T8): cancellarli o ridurli a
   `pub(crate)`. Nota: 17 altri sono usati **solo dai test**, che essendo crate
   separati richiedono `pub` — decisione diversa. Questa sussume T4, T5, T6, T38.
5. **Gli 8.7 MB di `.sig` convertiti** (T27): committarli o generarli come passo
   di build.

**Nota sulla decisione 1**: la soglia 16 era una difesa contro i pattern
troncati. Dopo l'iterazione 53 i falsi positivi sono **0 gia' senza soglia**, su
entrambi i corpora — resta utile come cintura di sicurezza, non come necessita'.

## 7. Altri comandi utili

```bash
# LA DEMO (T18) — parte da qui per capire lo stato della catena
cargo run --release -q -p rustre-flirt-apply --example flirt_demo
# e il README del crate spiega COME LEGGERE i numeri:
#   crates/rustre-flirt-apply/README.md

# strumenti di misura
cargo run --release -q -p rustre-flirt-apply --example self_match_experiment
cargo run --release -q -p rustre-flirt-apply --example cross_binary_match
cargo run --release -q -p rustre-flirt-apply --example recall_ceiling
cargo run --release -q -p rustre-flirt-apply --example dead_public_modules
cargo run --release -q -p rustre-flirt-apply --example prototype_circularity

# copertura prototipi Level 7
cargo run --release -p rustre-flirt-apply --example prototype_coverage -- tests/decompiler_corpus/prototypes.json

# diagnostica del ponte FLIRT→type recovery
RUSTRE_FLIRT_DEBUG=1 ./target/release/examples/dump_decompile.exe <bin> <outdir>
```

## 8. Trappole di questo repo (costate tempo davvero)

- **Lock di build saturo:** decine di `cargo` di altri agenti. Succede
  regolarmente (misurati 31 e 64 processi). Se va in timeout: dichiarare la
  verifica **pendente**, non spuntare nulla, non pubblicare un verde vecchio, e
  **non terminare** quei processi.
- Il workspace viene rotto da **agenti concorrenti** su altri crate
  (`rustre-demangle`, `rustre-decompiler`, …). **Ritentare** prima di riparare:
  nell'iterazione 43 si e' risolto da solo. Non mettere mano ai crate altrui.
- `cargo build` non compila i `#[cfg(test)]`: un `use` segnalato *unused* puo'
  servire solo ai test. Verificare con `cargo test`, non col solo build.
- Verificare per `grep` vale quanto il pattern: serve un **test che enumeri** i
  consumatori, non una ricerca.
- I file `runtime_prototypes.rs` e `mingw_runtime_sigs.rs` sono **generati**:
  si rigenerano, non si editano.
