#!/usr/bin/env python3
"""Arieta' degli ARGOMENTI ai siti di chiamata contro i prototipi PUBBLICATI.

Perche' esiste (2026-08-29): `callsite_consistency.py` misura la coerenza
INTERNA - definizione contro chiamata nello stesso progetto - e non sa
distinguere «coerente e giusto» da «coerente e sbagliato due volte».

Misurato quel giorno: su `pthread_mutex_unlock` (arieta' vera 1) path A chiama
con 2 argomenti E la definisce con 2, quindi risulta COERENTE; path B chiama
con 0, quindi risulta UNDER. Contro la verita' esterna path A sbaglia due
volte e path B una.

Questa misura usa `prototypes.json` - 136 firme estratte dagli header mingw,
con provenienza per riga - e conta quanti SITI passano il numero GIUSTO.
Esito allora: path A 314/409 (76%), path B 368/407 (90%).

⚠ Copre ~1% dei siti (solo funzioni di runtime con prototipo noto) ed e' un
campione NON casuale. Non dice «B e' corretto al 90%»: dice «dove una verita'
verificabile esiste, B ci va vicino piu' spesso».

Le variadiche (arieta' -1 in `prototypes.json`) sono ESCLUSE: un numero
qualunque di argomenti e' legittimo.
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from callsite_consistency import chiamate  # stessa scansione, stesse guardie


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--path-b", action="store_true", help="i file *.hlil.c")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--esempi", type=int, default=6)
    a = ap.parse_args()

    proto = json.load(open(os.path.join(HERE, "prototypes.json")))["prototypes"]
    vere = {n: v["arity"] for n, v in proto.items()
            if isinstance(v.get("arity"), int) and v["arity"] >= 0}

    suffisso = ".hlil.c" if a.path_b else ".c"
    giusti = sbagliati = 0
    det: collections.Counter = collections.Counter()

    for radice, _, files in os.walk(a.out_dir):
        blob = []
        for f in files:
            if not f.endswith(suffisso):
                continue
            if not a.path_b and f.endswith(".hlil.c"):
                continue
            blob.append(open(os.path.join(radice, f), encoding="utf-8",
                             errors="replace").read())
        if not blob:
            continue
        testo = chr(10).join(blob)
        for nome, ar in vere.items():
            for k in chiamate(testo, nome):
                if k == ar:
                    giusti += 1
                else:
                    sbagliati += 1
                    det[(nome, ar, k)] += 1

    tot = giusti + sbagliati
    pct = (100 * giusti // tot) if tot else 0

    if a.json:
        print(json.dumps({
            "sites": tot,
            "correct": giusti,
            "wrong": sbagliati,
            "correct_pct": pct,
            "prototypes_used": len(vere),
        }))
        return 0

    print(f"prototipi con arieta' nota : {len(vere)}")
    print(f"siti su funzioni note      : {tot}")
    print(f"  argomenti CORRETTI       : {giusti} ({pct}%)")
    print(f"  sbagliati                : {sbagliati}")
    if tot == 0:
        print("  *** ATTENZIONE: nessun sito trovato. Albero vuoto o path sbagliato? ***")
    for (nome, ar, k), c in det.most_common(a.esempi):
        verso = "MENO" if k < ar else "PIU'"
        print(f"    {nome}: vera {ar}, chiamata {k}  x{c}  (ne passa {verso})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
