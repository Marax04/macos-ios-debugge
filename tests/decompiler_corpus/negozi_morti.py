#!/usr/bin/env python3
"""Negozi morti `V = (__int64)&off_X;` con liveness PER ASSEGNAZIONE.

Il conteggio per NOME (round 1223) sottostima: una variabile riciclata altrove
nella stessa funzione risulta "viva" anche quando QUELL'assegnazione e' morta.
Qui si guarda solo l'intervallo fra l'assegnazione e la successiva
riassegnazione della stessa variabile: se in quell'intervallo il nome non viene
LETTO, il negozio e' morto e l'`extern` che crea e' rimovibile.
"""
import re, sys, glob, os, json

ASSEG = re.compile(r'^(\s*)([A-Za-z_]\w*)\s*=\s*\(__int64\)&(off_[0-9A-Fa-f]+)\s*;\s*$')
RIASSEG = re.compile(r'^\s*([A-Za-z_]\w*)\s*=[^=]')

def morti_del_file(testo):
    ext = set(re.findall(r'^extern\s+\w+\s+(off_[0-9A-Fa-f]+)\s*;', testo, re.M))
    L = testo.split('\n')
    out = []
    for i, l in enumerate(L):
        m = ASSEG.match(l)
        if not m:
            continue
        var, sym = m.group(2), m.group(3)
        if sym not in ext:          # gia' definito: non blocca il link
            continue
        letto = False
        for j in range(i + 1, len(L)):
            r = RIASSEG.match(L[j])
            if r and r.group(1) == var:
                break               # riassegnata senza essere letta -> morta
            if re.search(r'\b' + re.escape(var) + r'\b', L[j]):
                letto = True
                break
        if not letto:
            out.append((i + 1, var, sym))
    return out, ext

def main(dirs):
    tot_ass = tot_morti = 0
    simboli = set()
    per_dir = {}
    for d in dirs:
        n_ass = n_morti = 0
        syms = set()
        for f in glob.glob(os.path.join(d, '*.hlil.c')):
            t = open(f, encoding='utf-8', errors='replace').read()
            if 'off_' not in t:
                continue
            morti, ext = morti_del_file(t)
            n_ass += len(re.findall(r'=\s*\(__int64\)&off_', t))
            n_morti += len(morti)
            syms.update(s for _, _, s in morti)
        per_dir[d] = (n_ass, n_morti, len(syms))
        tot_ass += n_ass; tot_morti += n_morti; simboli |= syms
        print(f"  {os.path.basename(d):18} assegnazioni={n_ass:5} MORTE={n_morti:4} extern_rimovibili={len(syms):4}")
    print(f"  {'TOTALE':18} assegnazioni={tot_ass:5} MORTE={tot_morti:4} extern_rimovibili={len(simboli):4}")
    if os.environ.get('NM_JSON'):
        json.dump({'assegnazioni': tot_ass, 'morte': tot_morti,
                   'extern': sorted(simboli)}, open(os.environ['NM_JSON'], 'w'), indent=1)

if __name__ == '__main__':
    main(sys.argv[1:] or ['.'])
