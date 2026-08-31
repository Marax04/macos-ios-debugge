# Guardia di esclusione per le misure — da installare in tests/decompiler_corpus/
#
# Perche' non `ps`: su Windows/Git-Bash `ps -W` stampa il PERCORSO dell'eseguibile
# e MAI gli argomenti. Quindi:
#   grep 'python'        -> conta i 16 server MCP: blocca sempre  (falso positivo)
#   grep 'behavior\.py'  -> non corrisponde mai:   non blocca mai (falso negativo)
# Entrambe le versioni provate oggi erano inutilizzabili, in direzioni opposte.
#
# Un lock file non ha questo problema: nomina il lavoro, non la categoria.

LOCK=/c/Users/Fra/Desktop/RustRE/tests/decompiler_corpus/.misura.lock

prendi_lock() {
    if [ -f "$LOCK" ]; then
        pid=$(cut -d' ' -f1 "$LOCK" 2>/dev/null)
        # il lock e' VIVO solo se il pid esiste ancora
        if kill -0 "$pid" 2>/dev/null; then
            echo "ABORT: misura gia' in corso -> $(cat "$LOCK")"
            return 1
        fi
        echo "lock STANTIO rimosso: $(cat "$LOCK")"   # crash precedente
        rm -f "$LOCK"
    fi
    echo "$$ $(date '+%Y-%m-%d %H:%M:%S') $*" > "$LOCK"
    trap 'rm -f "$LOCK"' EXIT INT TERM
    return 0
}
