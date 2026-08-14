# Decompiler Reality Check — cargo-zyphora.exe

Verifica reale al 2026-07-08.

## Dati verificati REALI (non fake)

### Function detection
- **RustRE `analysis_fn_detect_functions_path`**: 2319 funzioni rilevate (path-based)
- **RustRE `analyze.function`**: 2336 funzioni rilevate (session-based)
- **IDA Pro baseline**: 1456 funzioni, 395 nominate

RustRE detects **~60% MORE funzioni** di IDA. Potrebbe essere overdetection (falsi positivi da HeuristicGap+ProloguePattern che rilevano stessa funzione due volte con confidence diverse) oppure migliore heuristica. Rimane da verificare quali sono vere e quali no.

### Disassembly
- **RustRE `disasm.at`**: output x86_64 corretto, verificato istruzione per istruzione:
  ```
  0x140001100: 650f85b0070000 → jne 00000001400018B7h
  0x140001107: 66c7060101      → mov word ptr [rsi], 101h
  0x14000110c: e997090000      → jmp 0000000140001AA8h
  ```
  Byte encoding corretto, sintassi Intel corretta.

### Decompilation
- **RustRE `decompile.function`**: FUNZIONA, ma qualità 3/10
- Output di esempio (sub_140000000):
  ```c
  __int64 __fastcall sub_140000000() {
      v3 = pop();
      [v2] = [v2] + al;
      [v1] = [v1] + al;
      [v1+v1] = [v1+v1] + al;
      [v1] = [v1] + al;
      return;
  }
  ```
  - IR level: PseudoC
  - Confidence: 50%
  - Variables inferred: 0
  - Call sites: 0

vs Hex-Rays (IDA) su stessa funzione produrrebbe qualcosa tipo:
```c
int __fastcall entry_point() {
    // proper vars, proper flow, function calls resolved
    ...
}
```

## Bug reali scoperti

### Bug integrazione: function DB non condiviso
`analysis_fn_detect_functions_path` (crate rustre-analysis-fn) e `decompile.function` (session state) NON condividono il registry:
- `analysis_fn_detect_functions_path` restituisce 2319 funzioni con indirizzi validi
- Chiamare `decompile.function` su uno di quegli indirizzi → "no function detected"
- Servono chiamate separate a `analyze.function` per popolare il session state

Impatto: workflow che vuole "detect all funs then decompile them" richiede DUE chiamate per funzione. Inefficiente.

Fix: `project.open` dovrebbe eseguire auto-detect e popolare il session state, oppure `decompile.function` dovrebbe fallback su `analyze.function` automaticamente.

### Qualità pseudo-C bassa
Output usa v1/v2/v3 generici, non trace variables reali, non risolve calls, non emette control-flow strutturato (if/while/for). Serve:
1. Variable naming heuristics
2. Type inference (già presente in rustre-decompiler-type ma non wired in output)
3. Control-flow structuring (già in rustre-decompiler-cfs ma disconnesso)
4. Call resolution via IAT

## Verdetto

- **Struttura MCP: SOLIDA** — 4130 tools, 0 crash, 114 categorie a 0 mismatch (Python ground truth)
- **Disasm: production-quality** — output verificato corretto
- **Function detection: over-eager ma reale** — trova più cose di IDA (per meglio o peggio)
- **Decompiler: prototipo** — funziona ma output non paragonabile a Hex-Rays. Servono 2-3 mesi di lavoro dedicato per raggiungere qualità 8/10
- **Simboli**: nessun nome derivato (tutti `sub_XXX`). IDA usa PDB per 395 nomi. RustRE dovrebbe importare PDB via rustre-symbols-pdb (già presente).
