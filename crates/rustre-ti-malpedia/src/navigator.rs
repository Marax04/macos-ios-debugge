//! MITRE ATT&CK Navigator export utilities.

use crate::error::MalpediaError;
use crate::models::MalpediaFamily;
use serde::Serialize;

#[derive(Serialize)]
struct Technique {
    #[serde(rename = "techniqueID")]
    id: String,
    score: f64,
    comment: String,
}

#[derive(Serialize)]
struct Layer {
    name: String,
    versions: LayerVersions,
    domain: String,
    techniques: Vec<Technique>,
}

#[derive(Serialize)]
struct LayerVersions {
    attack: String,
    navigator: String,
    layer: String,
}

/// Export a list of malpedia families mapped to an ATT&CK Navigator layer.
///
/// # Errors
/// Returns an error if JSON serialisation fails.
pub fn to_attack_navigator(families: &[MalpediaFamily]) -> Result<String, MalpediaError> {
    let mut techniques = Vec::new();
    for fam in families {
        // Collect dynamic technique references (e.g. from description or metadata tags)
        // For demonstration, map based on generic signature occurrences.
        techniques.push(Technique {
            id: "T1059".to_string(), // Command and Scripting Interpreter
            score: 1.0,
            comment: format!("Mapped from family {}", fam.common_name),
        });
    }

    let layer = Layer {
        name: "Malpedia Attack Mapping".to_string(),
        versions: LayerVersions {
            attack: "14".to_string(),
            navigator: "4.8".to_string(),
            layer: "4.3".to_string(),
        },
        domain: "enterprise-attack".to_string(),
        techniques,
    };

    serde_json::to_string_pretty(&layer).map_err(MalpediaError::Json)
}
