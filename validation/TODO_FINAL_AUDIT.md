# TODO: Audit finale completo

Dopo R33 (PARTIAL→FULL) + R34 (NONE→COVERED) + retry generici dei failed:

**Rifare audit completo:**
```bash
python validation/dump_tools.py        # conta tool MCP totali
python validation/coverage_breakdown.py # ricalcola FULL/PARTIAL/NONE/INTERNAL
python validation/exercise_v3.py        # esercita tutti i tool su cargo-zyphora.exe
```

**Baseline pre-R33/R34** (da superare):
| Categoria | Pre | Target |
|-----------|-----|--------|
| FULL | 3 | ~179 (tutti meno INTERNAL) |
| PARTIAL | 81 | 0 |
| NONE | 95 | 0 |
| INTERNAL | 24 | 24 (invariato) |

**Tool MCP totali**: 133 → target 400+

**Tool working rate**: 114/133 (86%) → target >95%

Salva report finale in `validation/R_FINAL_AUDIT.md`.
