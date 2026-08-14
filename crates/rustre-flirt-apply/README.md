# FLIRT: dalla libreria al nome della funzione

Riconoscimento di funzioni di libreria in binari senza simboli, in tre crate:

| crate | ruolo |
|---|---|
| `rustre-flirt` | tipi condivisi, CRC canonico, codec dell'header `.sig` |
| `rustre-flirt-gen` | genera firme da archivi `.a` / `.lib` |
| `rustre-flirt-apply` | legge i `.sig`, scansiona i binari, applica i nomi |

## La demo

```bash
cargo run --release -p rustre-flirt-apply --example flirt_demo
```

Percorre la catena intera e stampa cosa produce ogni stadio. Con
`libmingw32.a` contro un binario C del corpus:

```
== 1. archivio ==   31 membri, 31 oggetti  ->  43 pattern (34 con wildcard)
== 2. .sig ==       3078 byte, magic IDASGN
== 3. rilettura ==  43 firme su 43 scritte
== 4. scansione ==  target: 24 funzioni identificate
                    controllo: 0 identificazioni
```

**La colonna di controllo e' il punto.** Produrre nomi e' facile; il fatto che
*nessuno* compaia in un binario Go, che quelle funzioni non puo' contenere, e'
l'affermazione che vale la pena fare. Le due cifre si muovono insieme: quando il
container troncava i pattern al primo wildcard, il controllo ne mostrava 5.

Argomenti opzionali: `flirt_demo <archivio> <target> <controllo>`.

## Come leggere i numeri

Tre trappole gia' pagate in questo progetto, con lo strumento che le evita.

**Il recall va misurato contro cio' che il binario contiene, non contro il
numero di firme.** Un linker statico include solo i membri d'archivio che
servono: 522 firme da `libmingwex.a` producevano 4 nomi, e sembrava un recall
dell'1%. Ma solo 3 di quelle firme avevano i byte d'ingresso presenti nel
target — il matcher era **al tetto**, non lontano da esso.

```bash
cargo run --release -p rustre-flirt-apply --example recall_ceiling
```

Il tetto e' stretto su C e **lasco su C++**, dove i prologhi sono condivisi fra
istanze di template: li' "N trovabili" non significa "N mancate".

**L'auto-riconoscimento non misura il valore.** Riscansionare i byte da cui una
firma e' stata generata e' l'input piu' favorevole possibile: serve a provare
che qualcosa e' rotto, non che funziona.

```bash
cargo run --release -p rustre-flirt-apply --example self_match_experiment
```

**Serve sempre un binario di controllo.** Senza, un match non si distingue da un
falso positivo.

```bash
cargo run --release -p rustre-flirt-apply --example cross_binary_match
```

## Generare le proprie firme

```bash
cargo run --release -p rustre-flirt-gen --example harvest_archives -- out.sig <dir-con-archivi>
```

Accetta `.a`, `.lib` e `.rlib`. Il `.sig` prodotto e' in formato `IDASGN`, a
header di lunghezza variabile: il nome della libreria e' **ultimo**, preceduto
dalla sua lunghezza a offset 34. Gli offset sono di
`rustre_flirt::sig_header` — cinque componenti hanno implementato una propria
copia di quel layout, e ognuna era internamente coerente e sbagliata.

## Usarle nel decompiler

```bash
RUSTRE_SIGDB_DIR=<dir-con-sig> ./target/release/examples/dump_decompile.exe <bin> <out>
```

Carica **tutte** le `.sig` della cartella. Usa una cartella nuova per ogni
misura e controlla il conteggio nella traccia (`RUSTRE_FLIRT_DEBUG=1`): un
`.sig` dimenticato di una sessione precedente ha gia' contaminato una misura.
