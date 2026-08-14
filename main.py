import os
from collections import defaultdict

LINGUAGGI = {
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin Script",
    ".scala": "Scala", ".groovy": "Groovy",
    ".c": "C", ".h": "C/C++ Header", ".cpp": "C++", ".cxx": "C++",
    ".cc": "C++", ".hpp": "C/C++ Header", ".hxx": "C/C++ Header",
    ".hh": "C/C++ Header",
    ".rs": "Rust", ".go": "Go", ".swift": "Swift",
    ".py": "Python", ".pyi": "Python Stubs", ".pypredef": "Python Stubs",
    ".rb": "Ruby", ".lua": "Lua", ".pl": "Perl",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".fish": "Shell",
    ".bat": "Batch", ".cmd": "Batch", ".ps1": "PowerShell",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript/JSX", ".jsx": "JavaScript/JSX",
    ".html": "HTML", ".htm": "HTML", ".css": "CSS",
    ".scss": "SCSS", ".sass": "SASS", ".less": "LESS",
    ".vue": "Vue", ".svelte": "Svelte",
    ".json": "JSON", ".yaml": "YAML", ".yml": "YAML",
    ".toml": "TOML", ".xml": "XML", ".properties": "Properties",
    ".ini": "INI", ".env": "ENV", ".csv": "CSV", ".conf": "Config",
    ".gradle": "Gradle", ".cmake": "CMake", ".mk": "Makefile",
    ".md": "Markdown", ".rst": "reStructuredText",
    ".txt": "Text", ".adoc": "AsciiDoc",
    # Ghidra-specific
    ".sinc": "Sleigh", ".slaspec": "Sleigh", ".sla": "Sleigh (compiled)",
    ".pspec": "Processor Spec", ".ldefs": "Language Defs",
    ".cspec": "Compiler Spec", ".opinion": "Opinion",
    ".lang": "Language Def", ".rxg": "Ghidra Script",
    ".gdis": "Ghidra Script", ".gdb": "GDB Script",
    # Other code
    ".sql": "SQL", ".asm": "Assembly", ".s": "Assembly",
    ".proto": "Protobuf", ".graphql": "GraphQL", ".tf": "Terraform",
    ".idl": "IDL", ".y": "Yacc/Bison", ".l": "Lex",
    ".frag": "GLSL Shader", ".vm": "Velocity Template",
    ".jsh": "JShell", ".tex": "LaTeX",
    # Build/project
    ".sln": "Visual Studio Solution", ".vcxproj": "VS Project",
    ".vcproj": "VS Project", ".manifest": "Manifest",
    ".exports": "Exports", ".diff": "Diff/Patch",
    ".prf": "Profile", ".epf": "Eclipse Prefs",
    ".hints": "Hints", ".trans": "Translation",
    ".info": "Info", ".sample": "Sample", ".in": "Template",
    ".filter": "Filter", ".control": "Control",
}

# Estensioni binarie da ignorare completamente
BINARI = {
    ".jar", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
    ".whl", ".egg",
    ".class", ".pyc", ".pyo",
    ".exe", ".dll", ".so", ".dylib", ".lib", ".a", ".o",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".webp", ".tiff", ".tif",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".mp3", ".mp4", ".wav", ".au", ".ogg", ".flac",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".fidbf", ".gdt", ".sng", ".idx", ".dwarf",
    ".tlb", ".lshvector", ".typed", ".egg-info",
    ".pdburl", ".dockerignore", ".cfg",
}

def conta_righe_progetto():
    esclusioni_default = {
        "node_modules", ".git", "venv", ".venv", "env", "__pycache__",
        ".vscode", ".idea", "dist", "build"
    }

    percorso_base = input("Inserisci il percorso della cartella da analizzare: ").strip()
    extra_esclusione = input("Inserisci un altro file/cartella da escludere (opzionale): ").strip()

    tutte_esclusioni = esclusioni_default.copy()
    if extra_esclusione:
        tutte_esclusioni.add(extra_esclusione)

    if not os.path.exists(percorso_base):
        print("Il percorso specificato non esiste.")
        return

    totale_righe = 0
    file_analizzati = 0
    file_saltati_binari = 0
    righe_per_linguaggio = defaultdict(int)
    file_per_linguaggio = defaultdict(int)

    print(f"\nAnalisi avviata in: {percorso_base}")
    print(f"Esclusioni attive: {', '.join(sorted(tutte_esclusioni))}\n")

    for root, dirs, files in os.walk(percorso_base):
        dirs[:] = [d for d in dirs if d not in tutte_esclusioni]

        for nome_file in files:
            if nome_file in tutte_esclusioni:
                continue

            percorso_completo = os.path.join(root, nome_file)
            _, estensione = os.path.splitext(nome_file.lower())

            # Salta i binari
            if estensione in BINARI:
                file_saltati_binari += 1
                continue

            linguaggio = LINGUAGGI.get(
                estensione,
                f"Altro ({estensione})" if estensione else "Nessuna estensione"
            )

            try:
                with open(percorso_completo, "r", encoding="utf-8", errors="ignore") as f:
                    righe = sum(1 for _ in f)
                totale_righe += righe
                file_analizzati += 1
                righe_per_linguaggio[linguaggio] += righe
                file_per_linguaggio[linguaggio] += 1
            except Exception:
                pass

    classifica = sorted(righe_per_linguaggio.items(), key=lambda x: x[1], reverse=True)

    print("-" * 65)
    print(f"  ANALISI COMPLETATA AL 100%")
    print(f"  File analizzati (testo) : {file_analizzati:,}")
    print(f"  File saltati (binari)   : {file_saltati_binari:,}")
    print(f"  Totale righe di codice  : {totale_righe:,}")
    print("-" * 65)
    print(f"\n  {'LINGUAGGIO':<30} {'FILE':>6}  {'RIGHE':>10}  {'%':>6}")
    print("-" * 65)
    for linguaggio, righe in classifica:
        n_file = file_per_linguaggio[linguaggio]
        perc = (righe / totale_righe * 100) if totale_righe > 0 else 0
        print(f"  {linguaggio:<30} {n_file:>6}  {righe:>10,}  {perc:>5.1f}%")
    print("-" * 65)

if __name__ == "__main__":
    conta_righe_progetto()