//! Lightweight i18n / language-selection layer.
//!
//! Provides a small process-wide translation table. The active language
//! defaults to English; the launcher can swap it via `set_global_language`
//! before the main render loop kicks off.

use parking_lot::RwLock;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Language {
    #[default]
    English,
    Italian,
    Spanish,
    French,
    German,
}

impl Language {
    pub const fn code(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::Italian => "it",
            Self::Spanish => "es",
            Self::French => "fr",
            Self::German => "de",
        }
    }
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::Italian => "Italiano",
            Self::Spanish => "Español",
            Self::French => "Français",
            Self::German => "Deutsch",
        }
    }
    pub const fn all() -> [Self; 5] {
        [
            Self::English,
            Self::Italian,
            Self::Spanish,
            Self::French,
            Self::German,
        ]
    }
    pub const fn index(self) -> usize {
        match self {
            Self::English => 0,
            Self::Italian => 1,
            Self::Spanish => 2,
            Self::French => 3,
            Self::German => 4,
        }
    }
}

pub struct Translations {
    pub active: Language,
    table: HashMap<&'static str, [&'static str; 5]>,
}

impl Translations {
    pub fn new() -> Self {
        let mut table: HashMap<&'static str, [&'static str; 5]> = HashMap::new();
        // Each row is [en, it, es, fr, de].
        macro_rules! entry {
            ($k:expr, $en:expr, $it:expr, $es:expr, $fr:expr, $de:expr) => {
                table.insert($k, [$en, $it, $es, $fr, $de]);
            };
        }
        entry!("menu.file", "File", "File", "Archivo", "Fichier", "Datei");
        entry!(
            "menu.edit",
            "Edit",
            "Modifica",
            "Editar",
            "Édition",
            "Bearbeiten"
        );
        entry!(
            "menu.view",
            "View",
            "Vista",
            "Vista",
            "Affichage",
            "Ansicht"
        );
        entry!(
            "menu.analysis",
            "Analysis",
            "Analisi",
            "Análisis",
            "Analyse",
            "Analyse"
        );
        entry!(
            "menu.debug",
            "Debug",
            "Debug",
            "Depurar",
            "Débogage",
            "Debuggen"
        );
        entry!(
            "menu.window",
            "Window",
            "Finestra",
            "Ventana",
            "Fenêtre",
            "Fenster"
        );
        entry!("menu.help", "Help", "Aiuto", "Ayuda", "Aide", "Hilfe");
        entry!(
            "open_binary",
            "Open Binary…",
            "Apri Binario…",
            "Abrir binario…",
            "Ouvrir binaire…",
            "Binärdatei öffnen…"
        );
        entry!(
            "save_project",
            "Save Project",
            "Salva Progetto",
            "Guardar proyecto",
            "Enregistrer projet",
            "Projekt speichern"
        );
        entry!(
            "settings",
            "Settings",
            "Impostazioni",
            "Configuración",
            "Paramètres",
            "Einstellungen"
        );
        entry!(
            "about",
            "About",
            "Informazioni",
            "Acerca de",
            "À propos",
            "Über"
        );
        entry!("ok", "OK", "OK", "Aceptar", "OK", "OK");
        entry!(
            "cancel",
            "Cancel",
            "Annulla",
            "Cancelar",
            "Annuler",
            "Abbrechen"
        );
        entry!(
            "search",
            "Search",
            "Cerca",
            "Buscar",
            "Rechercher",
            "Suchen"
        );
        entry!(
            "loading",
            "Loading…",
            "Caricamento…",
            "Cargando…",
            "Chargement…",
            "Lädt…"
        );
        Self {
            active: Language::English,
            table,
        }
    }
    pub const fn set_language(&mut self, l: Language) {
        self.active = l;
    }
    pub fn t(&self, key: &str) -> &'static str {
        self.table.get(key).map_or_else(
            || key_to_owned_static_fallback(key),
            |row| row[self.active.index()],
        )
    }
}

// The lookup falls back to the key itself when no translation row exists.
// Returning &'static str here means we leak the original key reference; it
// is one of the few cases where the static-string lifetime is exactly
// what the call site needs.
const fn key_to_owned_static_fallback(key: &str) -> &'static str {
    // We cannot promote a borrowed str to 'static without leaking. Since
    // unknown keys should be diagnosed and fixed, fall back to a fixed
    // placeholder rather than leaking.
    let _ = key;
    "?"
}

pub static GLOBAL_TRANSLATIONS: std::sync::LazyLock<RwLock<Translations>> =
    std::sync::LazyLock::new(|| RwLock::new(Translations::new()));

pub fn current_language() -> Language {
    GLOBAL_TRANSLATIONS.read().active
}
pub fn set_global_language(l: Language) {
    GLOBAL_TRANSLATIONS.write().set_language(l);
}
pub fn t(key: &'static str) -> &'static str {
    GLOBAL_TRANSLATIONS.read().t(key)
}

#[doc(hidden)]
pub fn ensure_used_i18n() {
    for l in Language::all() {
        let _ = l.code();
        let _ = l.display_name();
        let _ = l.index();
    }
    let mut tr = Translations::new();
    tr.set_language(Language::Italian);
    let _ = tr.t("menu.file");
    let _ = current_language();
    set_global_language(Language::English);
    let _ = t("menu.file");
}
