#!/usr/bin/env python3
"""Leggibilita' del testo emesso: proxy OGGETTIVI, confrontabili fra i due path.

Perche' esiste
--------------
Nove metriche del protocollo misurano CORRETTEZZA (comportamento, arieta',
link, coerenza). Nessuna misura quanto il testo sia LEGGIBILE -- ed e' la sola
dimensione su cui path A potrebbe ancora avere ragione: path A ha 107 passate
testuali (`text_pass!`) che path B non ha, e molte lavorano sulla forma.

`rustre_decompiler_c::c_quality::QualityAnalyser` (1173 righe) misurerebbe
esattamente questo, ma e' dietro un gate spento e legge `pseudo_code`, cioe'
SOLO path A. Farla girare sul corpus richiede plumbing in Rust; questi proxy
danno un confronto subito, e sono onesti su cosa sono.

⚠ NON e' un punteggio di qualita': sono conteggi. Un numero piu' basso di
`goto` e' quasi sempre meglio; un numero piu' basso di righe puo' voler dire
piu' compatto O piu' incompleto. Vanno letti INSIEME, e accanto alle metriche
di correttezza -- da solo nessuno di questi dice se il testo e' giusto.

Uso: readability.py <out_dir> [--path-b] [--json]
"""
import os, re, sys, json, statistics

def unita(fname, path_b):
    if path_b:
        return fname.endswith(".hlil.c")
    return fname.endswith(".c") and not fname.endswith(".hlil.c")

RE_GOTO   = re.compile(r'^\s*goto\b', re.M)
RE_LABEL  = re.compile(r'^\s*\w+:\s*$', re.M)
RE_IF     = re.compile(r'^\s*(if|while|for|switch)\b', re.M)
RE_DECL   = re.compile(r'^\s+[A-Za-z_][\w \*]*\b\w+\s*(\[[^\]]*\])?;\s*$', re.M)
# 8290: la lista OMETTEVA uint32_t/int32_t/uint16_t/uint8_t - cioe' i tipi che
# path B emette di piu'. Misurato il 29-08: contava 36 dei 29098 cast rimossi
# da #8260, e dava il divario A/B come 2,22x invece di 4,08x. Una metrica di
# leggibilita' cieca ai tipi del path che deve sorvegliare.
RE_CAST   = re.compile(r'\(\s*(?:__int64|u?int(?:8|16|32|64)_t|unsigned|signed|char|short|int|long|void|float|double|size_t)\s*\*?\s*\)')

def misura(testo):
    righe = testo.split("\n")
    corpo = [r for r in righe if r.strip()]
    prof = 0; profmax = 0
    for r in righe:
        prof += r.count("{") - r.count("}")
        profmax = max(profmax, prof)
    return {
        "righe": len(corpo),
        "goto": len(RE_GOTO.findall(testo)),
        "etichette": len(RE_LABEL.findall(testo)),
        "controllo": len(RE_IF.findall(testo)),
        "dichiarazioni": len(RE_DECL.findall(testo)),
        "cast": len(RE_CAST.findall(testo)),
        "profondita_max": profmax,
        "riga_piu_lunga": max((len(r) for r in righe), default=0),
    }

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path_b = "--path-b" in sys.argv
    as_json = "--json" in sys.argv
    if not args:
        print(__doc__); return 2
    root = args[0]
    tot = {k: 0 for k in ("righe","goto","etichette","controllo","dichiarazioni","cast")}
    prof = []; lung = []; n = 0
    for b in sorted(os.listdir(root)):
        d = os.path.join(root, b)
        if not os.path.isdir(d): continue
        for f in sorted(os.listdir(d)):
            if not unita(f, path_b): continue
            try:
                t = open(os.path.join(d, f), encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            m = misura(t); n += 1
            for k in tot: tot[k] += m[k]
            prof.append(m["profondita_max"]); lung.append(m["riga_piu_lunga"])
    if n == 0:
        print("*** ATTENZIONE: nessuna unita' trovata. Non e' un punteggio di 0:")
        print("    e' la metrica che non ha visto nulla. Albero sbagliato, o")
        print("    --path-b su un albero senza .hlil.c?")
        return 1
    out = {"unita": n}
    for k, v in tot.items():
        out[k] = v
        out[k + "_per_unita"] = round(v / n, 2)
    out["profondita_mediana"] = statistics.median(prof)
    out["riga_piu_lunga_mediana"] = statistics.median(lung)
    if as_json:
        print(json.dumps(out)); return 0
    print(f"  unita' analizzate      : {n}")
    for k in ("righe","goto","etichette","controllo","dichiarazioni","cast"):
        print(f"  {k:22}: {tot[k]:8}   {out[k+'_per_unita']:8.2f} per unita'")
    print(f"  profondita' mediana    : {out['profondita_mediana']}")
    print(f"  riga piu' lunga (mediana): {out['riga_piu_lunga_mediana']}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
