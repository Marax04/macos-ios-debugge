"""Coerenza fra l'arieta' con cui una funzione e' DEFINITA e quella con cui e'
CHIAMATA, dentro lo stesso progetto emesso.

Come `cross_build.py`, non serve nessuna verita' esterna: se il codice emesso
si contraddice, uno dei due lati e' sbagliato. E' la metrica che `check.sh` non
puo' dare, perche' `gcc -std=gnu89` accetta `f(a,b,c)` contro `__int64 f();` —
una lista di parametri vuota e' una dichiarazione NON prototipata, non la
promessa di zero argomenti. E' la stessa cecita' che una volta lasciava leggere
11143/11144 con 2233 parametri fantasma.

⚠ Questo file e' stato RISCRITTO il 2026-08-25: CLAUDE.md lo documentava con
numeri precisi (10330 definizioni, 9756 OVER, 6042 UNDER su `base_0818`) ma non
esisteva in albero — vedi STATUS.md §158. I numeri di quella riga NON sono
quindi confrontabili con quelli prodotti qui, perche' non si sa quale
implementazione li avesse generati. Trattare l'output di oggi come una nuova
baseline, non come un confronto.

Uso:
    python callsite_consistency.py <out_dir> [--path-b] [--esempi N]

OVER  = la funzione e' chiamata con PIU' argomenti di quanti ne dichiara.
        Compila (dichiarazione non prototipata) ed e' silenziosamente sbagliato.
UNDER = e' chiamata con MENO argomenti: i restanti leggono spazzatura.
"""

import argparse
import os
import re
import sys
from collections import Counter, defaultdict

# `tipo nome(params) {` a inizio riga: una DEFINIZIONE.
DEF = re.compile(r"^[A-Za-z_][\w \*]*?\b(\w+)\s*\(([^)]*)\)\s*\{", re.M)
# Parole che aprono un costrutto, non una definizione.
KEYWORDS = {"if", "while", "for", "switch", "do", "else", "return", "sizeof"}


def conta_parametri(testo: str):
    """Numero di parametri dichiarati, o None se VARIADICA.

    ⚠ Una variadica (`__report_error(fmt, ...)`) non e confrontabile: ogni
    chiamata con meno argomenti dei parametri fissi + `...` sarebbe un UNDER
    fasullo. Sui primi esempi erano 8 su 12.
    """
    t = testo.strip()
    if "..." in t:
        return None
    if not t or t == "void":
        return 0
    # Nessuna virgola dentro parentesi annidate nelle firme emesse: split piano.
    return len([p for p in t.split(",") if p.strip()])


def conta_argomenti(testo: str) -> int:
    """Numero di argomenti a una chiamata, rispettando le parentesi annidate."""
    t = testo.strip()
    if not t:
        return 0
    n, liv = 1, 0
    for c in t:
        if c in "([":
            liv += 1
        elif c in ")]":
            liv -= 1
        elif c == "," and liv == 0:
            n += 1
    return n


def chiamate(testo: str, nome: str):
    """Ogni chiamata a `nome`: restituisce il numero di argomenti."""
    out = []
    i = 0
    while True:
        j = testo.find(nome + "(", i)
        if j < 0:
            return out
        i = j + len(nome) + 1
        # confine di parola a sinistra
        if j > 0 and (testo[j - 1].isalnum() or testo[j - 1] == "_"):
            continue
        # la definizione stessa non e' una chiamata: la si riconosce dal `{`
        liv, k = 1, i
        while k < len(testo) and liv:
            if testo[k] in "([":
                liv += 1
            elif testo[k] in ")]":
                liv -= 1
            k += 1
        if liv:
            continue
        coda = testo[k : k + 3].lstrip()
        if coda.startswith("{"):
            continue
        # ⚠ Una DICHIARAZIONE forward (`__int64 f();`) non e una chiamata.
        # Senza questo controllo ogni forward decl contava come «chiamata con 0
        # argomenti» e produceva un UNDER fasullo: sui primi esempi erano
        # TUTTI di quella forma (`def 2, chiamata 0`).
        # La si riconosce dal fatto che a sinistra del nome, sulla stessa riga,
        # c'e un TIPO — cioe la riga inizia con un identificatore e finisce con
        # `);` senza nulla in mezzo dopo la parentesi.
        inizio_riga = testo.rfind(chr(10), 0, j) + 1
        prefisso = testo[inizio_riga:j].strip()
        if coda.startswith(";") and prefisso and not prefisso.endswith(("=", "(", ",", "&", "!", "return")):
            continue
        out.append(conta_argomenti(testo[i : k - 1]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--path-b", action="store_true", help="i file *.hlil.c")
    ap.add_argument("--esempi", type=int, default=5)
    ap.add_argument("--json", action="store_true",
                    help="stampa un oggetto JSON invece del rapporto testuale, "
                         "cosi' che measure.sh possa portare i numeri in "
                         "metrics.json e SORVEGLIARLI. Senza questo, la metrica "
                         "si stampa e nessuno la confronta.")
    a = ap.parse_args()

    suffisso = ".hlil.c" if a.path_b else ".c"
    per_bucket = defaultdict(dict)  # bucket -> nome -> arieta' dichiarata
    testi = defaultdict(list)  # bucket -> [testo]

    for radice, _, files in os.walk(a.out_dir):
        bucket = os.path.basename(radice)
        for f in files:
            if not f.endswith(suffisso):
                continue
            if not a.path_b and f.endswith(".hlil.c"):
                continue
            t = open(os.path.join(radice, f), encoding="utf-8", errors="replace").read()
            testi[bucket].append(t)
            for m in DEF.finditer(t):
                nome = m.group(1)
                if nome in KEYWORDS:
                    continue
                n_par = conta_parametri(m.group(2))
                if n_par is not None:
                    per_bucket[bucket][nome] = n_par

    c = Counter()
    esempi = []
    for bucket, defs in per_bucket.items():
        blob = "\n".join(testi[bucket])
        for nome, dichiarata in defs.items():
            n_args = chiamate(blob, nome)
            # Se i siti passano un numero VARIABILE di argomenti, la funzione e'
            # verosimilmente VARIADICA e il difetto sta nella DEFINIZIONE ad
            # arieta' fissa, non nei singoli siti.
            #
            # Caso misurato: `__report_error` — variadica in mingw
            # (`const char *, ...`) — e' emessa come
            # `void __report_error(uint64_t a1, a2, a3, a4)` e chiamata con 0,
            # 1, 2 e 3 argomenti. Contarla come 12 UNDER attribuirebbe a ogni
            # sito un difetto che e' uno solo, e a monte.
            if len(set(n_args)) > 2:
                c["variadiche non riconosciute"] += 1
                if len(esempi) < a.esempi:
                    esempi.append(
                        f"VARIADICA? {bucket}/{nome}: def {dichiarata}, "
                        f"chiamate {sorted(set(n_args))}"
                    )
                continue
            for n_arg in n_args:
                c["siti di chiamata"] += 1
                if n_arg > dichiarata:
                    c["OVER"] += 1
                    if len(esempi) < a.esempi:
                        esempi.append(f"OVER  {bucket}/{nome}: def {dichiarata}, chiamata {n_arg}")
                elif n_arg < dichiarata:
                    c["UNDER"] += 1
                    if len(esempi) < a.esempi:
                        esempi.append(f"UNDER {bucket}/{nome}: def {dichiarata}, chiamata {n_arg}")
                else:
                    c["coerenti"] += 1

    tot_def = sum(len(v) for v in per_bucket.values())
    if a.json:
        import json as _json
        siti = c["siti di chiamata"]
        print(_json.dumps({
            "definitions": tot_def,
            "call_sites": siti,
            "consistent": c["coerenti"],
            "over": c["OVER"],
            "under": c["UNDER"],
            "variadic_unrecognised": c["variadiche non riconosciute"],
            "consistency_pct": (100 * c["coerenti"] // siti) if siti else 0,
        }))
        return 0
    print(f"definizioni ispezionate : {tot_def}")
    print(f"siti di chiamata        : {c['siti di chiamata']}")
    print(f"  coerenti              : {c['coerenti']}")
    print(f"  OVER  (piu' argomenti): {c['OVER']}")
    print(f"  UNDER (meno argomenti): {c['UNDER']}")
    print(f"  variadiche non riconosciute: {c['variadiche non riconosciute']}")
    if c["siti di chiamata"]:
        buoni = 100 * c["coerenti"] // c["siti di chiamata"]
        print(f"  coerenza              : {buoni}%")
    for e in esempi:
        print("   ", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
