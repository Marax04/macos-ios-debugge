#!/usr/bin/env python3
"""Cancello VELOCE: invarianti testuali su un albero emesso (~2 min, 1 bucket).

Non sostituisce `behavior.py` (l'unico giudice), lo PRECEDE: scarta in fretta
le idee morte senza pagare i ~60 minuti della misura comportamentale.

    python cancello.py <dir> [--json out.json]
    python cancello.py <dopo> --contro <prima>

Ogni riga e' un invariante che una modifica puo' migliorare o peggiorare; il
confronto stampa il SEGNO, mai un numero assoluto isolato.
"""
import re, sys, os, glob, json

RE = {
 'extern_off'    : re.compile(r'^extern\s+\w+\s+(?:off_|sub_)[0-9A-Fa-f]+\s*;', re.M),
 'dispatch_rel32': re.compile(r'=\s*\(int64_t\)\(int32_t\)\*\s*\(uint32_t \*\)\s*\(\s*\w+\s*\+'),
 'switch'        : re.compile(r'\bswitch \('),
 'goto'          : re.compile(r'\bgoto '),
 'for'           : re.compile(r'\bfor \('),
 'while'         : re.compile(r'\bwhile \('),
 'struct'        : re.compile(r'^\s*struct [A-Za-z_]', re.M),
 'campi'         : re.compile(r'->field_[0-9A-Fa-f]+'),
 'xmm_grezzi'    : re.compile(r'\bvar_xmm\d'),
 'intrinseci'    : re.compile(r'\b_mm_[a-z0-9_]+\('),
 'jumpout'       : re.compile(r'\bJUMPOUT\b'),
}

def scan(d):
    m = {k: 0 for k in RE}
    m['file'] = 0; m['righe'] = 0
    for f in glob.glob(os.path.join(d, '*.hlil.c')):
        t = open(f, encoding='utf-8', errors='replace').read()
        m['file'] += 1
        m['righe'] += t.count('\n')
        for k, r in RE.items():
            m[k] += len(r.findall(t))
    return m

# direzione desiderata: +1 = salire e' meglio, -1 = scendere e' meglio, 0 = neutro
VERSO = {'extern_off': -1, 'dispatch_rel32': -1, 'goto': -1, 'jumpout': -1,
         'xmm_grezzi': -1, 'switch': +1, 'for': +1, 'while': 0, 'struct': +1,
         'campi': +1, 'intrinseci': +1, 'righe': 0, 'file': 0}

def main():
    a = sys.argv[1]
    contro = None
    if '--contro' in sys.argv:
        contro = sys.argv[sys.argv.index('--contro') + 1]
    ma = scan(a)
    if not contro:
        for k in ['file', 'righe'] + sorted(RE):
            print(f"  {k:15} {ma[k]}")
        if '--json' in sys.argv:
            json.dump(ma, open(sys.argv[sys.argv.index('--json') + 1], 'w'), indent=1)
        return 0
    mb = scan(contro)
    peggio = []
    print(f"  {'invariante':15} {'prima':>8} {'dopo':>8}  {'delta':>7}")
    for k in ['file', 'righe'] + sorted(RE):
        d = ma[k] - mb[k]
        v = VERSO.get(k, 0)
        segno = '' if d == 0 else ('  MEGLIO' if d * v > 0 else ('  PEGGIO' if d * v < 0 else '  ='))
        if d * v < 0 and v != 0:
            peggio.append(k)
        print(f"  {k:15} {mb[k]:>8} {ma[k]:>8}  {d:>+7}{segno}")
    if ma['file'] != mb['file']:
        print(f"\n  ATTENZIONE: numero di file CAMBIATO ({mb['file']} -> {ma['file']}): "
              f"popolazione diversa, i delta non sono confrontabili.")
        return 3
    if peggio:
        print(f"\n  REGRESSIONE su: {', '.join(peggio)}")
        return 1
    print("\n  nessuna regressione sugli invarianti")
    return 0

if __name__ == '__main__':
    sys.exit(main())
