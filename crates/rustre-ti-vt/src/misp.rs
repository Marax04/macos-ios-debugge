//! MISP-compatible event export from VT file reports.

use serde::{Deserialize, Serialize};

use crate::models::VtFileReport;

/// Simplified MISP event structure for VT export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEvent {
    pub info: String,
    pub threat_level_id: u8,
    pub analysis: u8,
    pub distribution: u8,
    pub attributes: Vec<MispAttribute>,
    pub tags: Vec<MispTag>,
}

/// A single MISP attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAttribute {
    pub category: String,
    #[serde(rename = "type")]
    pub attr_type: String,
    pub value: String,
    pub to_ids: bool,
    pub comment: String,
}

/// A MISP tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispTag {
    pub name: String,
    pub colour: String,
}

/// Convert a `VtFileReport` to a MISP event.
///
/// The generated event contains:
/// - SHA-256 / MD5 / SHA-1 hashes as `Payload delivery` attributes
/// - File name (if available) as `Payload delivery` `filename` attribute
/// - Detection family names from engine results as tags
#[must_use]
pub fn to_misp_event(report: &VtFileReport) -> MispEvent {
    let mut attributes = Vec::new();

    // Hashes.
    attributes.push(MispAttribute {
        category: "Payload delivery".to_string(),
        attr_type: "sha256".to_string(),
        value: report.sha256.clone(),
        to_ids: true,
        comment: format!(
            "VT score: {}/{} malicious",
            report.last_analysis_stats.malicious,
            report.last_analysis_stats.total()
        ),
    });

    if !report.md5.is_empty() {
        attributes.push(MispAttribute {
            category: "Payload delivery".to_string(),
            attr_type: "md5".to_string(),
            value: report.md5.clone(),
            to_ids: true,
            comment: String::new(),
        });
    }

    if !report.sha1.is_empty() {
        attributes.push(MispAttribute {
            category: "Payload delivery".to_string(),
            attr_type: "sha1".to_string(),
            value: report.sha1.clone(),
            to_ids: true,
            comment: String::new(),
        });
    }

    if let Some(ref name) = report.name
        && !name.is_empty() {
            attributes.push(MispAttribute {
                category: "Payload delivery".to_string(),
                attr_type: "filename".to_string(),
                value: name.clone(),
                to_ids: false,
                comment: String::new(),
            });
        }

    if report.size > 0 {
        attributes.push(MispAttribute {
            category: "Payload delivery".to_string(),
            attr_type: "size-in-bytes".to_string(),
            value: report.size.to_string(),
            to_ids: false,
            comment: String::new(),
        });
    }

    // Collect unique detection family names.
    let mut families: std::collections::HashSet<String> = std::collections::HashSet::new();
    for result in report.last_analysis_results.values() {
        if let Some(ref det) = result.result
            && !det.is_empty() {
                families.insert(det.clone());
            }
    }

    let mut tags: Vec<MispTag> = families
        .into_iter()
        .map(|f| MispTag {
            name: format!("malware:family={f}"),
            colour: "#ff0000".to_string(),
        })
        .collect();

    for vt_tag in &report.tags {
        tags.push(MispTag {
            name: format!("vt:tag={vt_tag}"),
            colour: "#ff6600".to_string(),
        });
    }

    // Threat level: 1=High if malicious > threshold, else 3=Low.
    let threat_level_id = if report.last_analysis_stats.malicious >= 5 { 1 } else { 3 };

    MispEvent {
        info: format!(
            "VirusTotal file report: {} ({} malicious)",
            report.name.as_deref().unwrap_or(&report.sha256),
            report.last_analysis_stats.malicious
        ),
        threat_level_id,
        analysis: 2, // Completed
        distribution: 0, // Organisation only
        attributes,
        tags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{VtEngineResult, VtFileReport, VtStats};
    use std::collections::HashMap;

    fn sample_report() -> VtFileReport {
        let mut results = HashMap::new();
        results.insert(
            "Engine1".to_string(),
            VtEngineResult {
                category: "malicious".to_string(),
                engine_name: "Engine1".to_string(),
                result: Some("Ransomware.WannaCry".to_string()),
                method: "blacklist".to_string(),
            },
        );
        VtFileReport {
            sha256: "abc123sha256".to_string(),
            md5: "abc123md5".to_string(),
            sha1: "abc123sha1".to_string(),
            name: Some("wannacry.exe".to_string()),
            size: 8192,
            type_tag: "peexe".to_string(),
            last_analysis_stats: VtStats {
                malicious: 60,
                suspicious: 5,
                undetected: 5,
                harmless: 0,
                timeout: 1,
            },
            last_analysis_results: results,
            first_submission_date: 1_500_000_000,
            tags: vec!["ransomware".to_string()],
        }
    }

    #[test]
    fn test_misp_event_from_report() {
        let report = sample_report();
        let event = to_misp_event(&report);

        assert!(event.info.contains("wannacry.exe"));
        assert_eq!(event.threat_level_id, 1); // High
        assert_eq!(event.analysis, 2);

        // Check SHA-256 attribute.
        let sha256_attr = event.attributes.iter().find(|a| a.attr_type == "sha256");
        assert!(sha256_attr.is_some());
        assert_eq!(sha256_attr.unwrap().value, "abc123sha256");
        assert!(sha256_attr.unwrap().to_ids);

        // Check filename attribute.
        let fname_attr = event.attributes.iter().find(|a| a.attr_type == "filename");
        assert!(fname_attr.is_some());
    }

    #[test]
    fn test_misp_event_tags() {
        let report = sample_report();
        let event = to_misp_event(&report);
        
        assert!(!event
            .tags
            .iter()
            .filter(|t| t.name.starts_with("malware:family="))
            .map(|t| t.name.as_str()).next().is_none());
    }

    #[test]
    fn test_misp_event_serialization() {
        let event = to_misp_event(&sample_report());
        let json = serde_json::to_string(&event).unwrap();
        let decoded: MispEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.threat_level_id, 1);
    }

    #[test]
    fn test_misp_low_threat_level() {
        let report = VtFileReport {
            sha256: "abc".to_string(),
            md5: "def".to_string(),
            sha1: "ghi".to_string(),
            name: None,
            size: 0,
            type_tag: String::new(),
            last_analysis_stats: VtStats {
                malicious: 1,
                ..VtStats::default()
            },
            last_analysis_results: HashMap::new(),
            first_submission_date: 0,
            tags: vec![],
        };
        let event = to_misp_event(&report);
        assert_eq!(event.threat_level_id, 3); // Low
    }
}
