#!/usr/bin/env python3
"""Genera voci di `behavior_spec.json` leggendo le firme dal C EMESSO.

Perche': gli harness sono scritti a mano, e sono 62 su 110 792 funzioni emesse
(0,06%). Tre modifiche di fila con guadagni strutturali grandi hanno misurato
ZERO, non perche' non servissero ma perche' la metrica copre 15 funzioni
distinte. Il collo di bottiglia non e' correggere il decompilatore: e' poterlo
misurare.

Copre lo scaglione SICURO (round 1232): argomenti scalari, ~10% delle funzioni.
Per i puntatori serve costruire la memoria puntata -- fase successiva.

    python genera_harness.py <dir_bucket> [--max N] [--out spec.json]

⚠ Genera SOLO la specifica. L'oracolo resta l'originale compilato dai sorgenti:
questo non inventa risultati attesi, li fa produrre a `behavior.py`.
"""
import re, sys, os, glob, json, random

SCAL = {
    'int': (-2**31, 2**31-1), 'unsigned int': (0, 2**32-1),
    'int32_t': (-2**31, 2**31-1), 'uint32_t': (0, 2**32-1),
    '__int64': (-2**63, 2**63-1), 'int64_t': (-2**63, 2**63-1),
    'uint64_t': (0, 2**64-1), 'unsigned __int64': (0, 2**64-1),
    'char': (-128, 127), 'unsigned char': (0, 255), 'uint8_t': (0, 255),
    'short': (-2**15, 2**15-1), 'uint16_t': (0, 2**16-1),
}
# valori che scoprono piu' difetti dei casuali puri
NOTEVOLI = [0, 1, -1, 2, 255, 256, -128, 127, 2**31-1, -2**31, 2**63-1]

FIRMA = re.compile(r'^([A-Za-z_][\w \*]*?)\s+([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*$', re.M)

def firma_di(testo):
    """Riga di DEFINIZIONE (non dichiarazione): finisce con `)` e la riga dopo apre `{`."""
    righe = testo.split('\n')
    for i, l in enumerate(righe):
        s = l.rstrip()
        if not s.endswith(')') or '(' not in s or ';' in s or '=' in s:
            continue
        if s.startswith((' ', '\t', '//', '#', 'extern', 'static')):
            continue
        if i + 1 < len(righe) and righe[i+1].strip().startswith('{'):
            m = FIRMA.match(s)
            if m:
                return m.group(1).strip(), m.group(2), m.group(3).strip()
    return None

def tipi_argomenti(args):
    if args in ('', 'void'):
        return []
    fuori = []
    for a in args.split(','):
        a = a.strip()
        if not a:
            return None
        parti = a.split()
        tipo = ' '.join(parti[:-1]) if len(parti) > 1 else a
        tipo = tipo.replace('const ', '').strip()
        if tipo.endswith('*') or tipo not in SCAL:
            return None          # non scalare: fuori dallo scaglione sicuro
        fuori.append(tipo)
    return fuori

def valori(tipi, n, rng):
    fuori = []
    for _ in range(n):
        riga = []
        for t in tipi:
            lo, hi = SCAL[t]
            v = rng.choice(NOTEVOLI) if rng.random() < 0.4 else rng.randint(lo, hi)
            riga.append(max(lo, min(hi, v)))
        fuori.append(riga)
    return fuori

def main():
    d = sys.argv[1]
    massimo = int(sys.argv[sys.argv.index('--max')+1]) if '--max' in sys.argv else 200
    rng = random.Random(20260831)
    funzioni = {}
    visti = tot = 0
    for f in sorted(glob.glob(os.path.join(d, '*.hlil.c'))):
        tot += 1
        t = open(f, encoding='utf-8', errors='replace').read()
        fi = firma_di(t)
        if not fi:
            continue
        ret, nome, args = fi
        if ret not in SCAL and ret != 'void':
            continue
        tipi = tipi_argomenti(args)
        if tipi is None or not tipi:
            continue          # senza argomenti: nessun ingresso da variare
        # ⚠ Il tipo DICHIARATO non basta: il decompilatore tipizza quasi tutti
        # i puntatori come `__int64`. Passare un intero casuale a un parametro
        # che viene DEREFERENZIATO produce un crash in entrambe le versioni,
        # cioe' un confronto che non esercita nulla. Misurato al round 1232:
        # l'89,6% delle funzioni con argomenti ne dereferenzia almeno uno.
        nomi = [a.strip().split()[-1].lstrip('*') for a in args.split(',') if a.strip()]
        usato_come_ptr = False
        for riga in t.splitlines():
            if '*(' not in riga and '->' not in riga and '[' not in riga:
                continue
            if any(re.search(r'\b' + re.escape(n) + r'\b', riga) for n in nomi):
                usato_come_ptr = True
                break
        if usato_come_ptr:
            continue
        visti += 1
        if len(funzioni) >= massimo:
            continue
        funzioni[nome] = {'ret': ret, 'args': tipi,
                          'inputs': valori(tipi, 8, rng)}
    print(f"  file esaminati            : {tot}")
    print(f"  con firma SCALARE pura    : {visti}  ({visti/max(tot,1)*100:.1f}%)")
    print(f"  voci generate             : {len(funzioni)}")
    if '--out' in sys.argv:
        p = sys.argv[sys.argv.index('--out')+1]
        nome_bucket = os.path.basename(os.path.normpath(d))
        json.dump({'buckets': {nome_bucket: {
            'out_dir': 'behav/out', 'functions': funzioni}}},
            open(p, 'w'), indent=1)
        print(f"  scritto                   : {p}")

if __name__ == '__main__':
    main()
