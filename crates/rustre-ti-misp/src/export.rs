//! Export MISP events to STIX 2.0 JSON.

use crate::models::{MispEvent, MispThreatLevel};

/// Export a `MispEvent` to a STIX 2.0 bundle JSON string.
#[must_use]
pub fn to_stix_bundle(event: &MispEvent) -> String {
    let mut objects: Vec<serde_json::Value> = Vec::new();

    // STIX Report object.
    let report = serde_json::json!({
        "type": "report",
        "spec_version": "2.1",
        "id": format!("report--{}", event.uuid),
        "name": event.info,
        "published": "2024-01-01T00:00:00Z",
        "object_refs": collect_stix_refs(event),
        "labels": event.tags.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
    });
    objects.push(report);

    // STIX Indicator objects from attributes.
    for attr in &event.attributes {
        if attr.to_ids
            && let Some(pattern) = attribute_to_stix_pattern(attr) {
                let indicator = serde_json::json!({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": format!("indicator--{}", attr.id.map_or_else(|| "0".to_string(), |id| id.to_string())),
                    "name": format!("{}: {}", attr.ty, attr.value),
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "labels": ["malicious-activity"],
                    "confidence": (attr.tags.len() + 1) * 20,
                });
                objects.push(indicator);
            }
    }

    // Threat level → STIX confidence.
    let confidence = match event.threat_level {
        MispThreatLevel::High => 85,
        MispThreatLevel::Medium => 60,
        MispThreatLevel::Low => 30,
        MispThreatLevel::Undefined => 10,
    };

    let bundle = serde_json::json!({
        "type": "bundle",
        "id": format!("bundle--{}", event.uuid),
        "spec_version": "2.1",
        "confidence": confidence,
        "objects": objects,
    });

    serde_json::to_string_pretty(&bundle).unwrap_or_default()
}

fn collect_stix_refs(event: &MispEvent) -> Vec<String> {
    let mut refs = Vec::new();
    for attr in &event.attributes {
        if attr.to_ids {
            refs.push(format!(
                "indicator--{}",
                attr.id.map_or_else(|| "0".to_string(), |id| id.to_string())
            ));
        }
    }
    refs
}

fn escape_stix_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn attribute_to_stix_pattern(attr: &crate::models::MispAttribute) -> Option<String> {
    let v = escape_stix_string(&attr.value);
    match attr.ty.as_str() {
        "ip-dst" | "ip-src" => Some(format!("[ipv4-addr:value = '{v}']")),
        "domain" | "hostname" => Some(format!("[domain-name:value = '{v}']")),
        "url" => Some(format!("[url:value = '{v}']")),
        "md5" => Some(format!("[file:hashes.MD5 = '{v}']")),
        "sha1" => Some(format!("[file:hashes.SHA-1 = '{v}']")),
        "sha256" => Some(format!("[file:hashes.SHA-256 = '{v}']")),
        "filename" => Some(format!("[file:name = '{v}']")),
        "email-src" | "email-dst" => {
            Some(format!("[email-message:from_ref.value = '{v}']"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        MispAnalysis, MispAttribute, MispDistribution, MispEvent, MispThreatLevel,
    };

    #[test]
    fn test_stix_bundle_structure() {
        let mut event = MispEvent::new(
            "STIX Export Test",
            MispThreatLevel::High,
            MispAnalysis::Completed,
            MispDistribution::All,
        );
        event.id = Some(1);
        let mut attr = MispAttribute::new("Payload delivery", "sha256", "deadbeef");
        attr.to_ids = true;
        attr.id = Some(10);
        event.add_attribute(attr);

        let stix = to_stix_bundle(&event);
        let json: serde_json::Value = serde_json::from_str(&stix).unwrap();
        assert_eq!(json["type"], "bundle");
        assert_eq!(json["spec_version"], "2.1");
        let objs = json["objects"].as_array().unwrap();
        assert!(objs.len() >= 2); // report + indicator
    }

    #[test]
    fn test_attribute_to_stix_pattern_ip() {
        let attr = MispAttribute::new("Network activity", "ip-dst", "1.2.3.4");
        let pattern = attribute_to_stix_pattern(&attr).unwrap();
        assert!(pattern.contains("ipv4-addr:value"));
        assert!(pattern.contains("1.2.3.4"));
    }

    #[test]
    fn test_attribute_to_stix_pattern_hash() {
        let attr = MispAttribute::new("Payload delivery", "sha256", "abc");
        let pattern = attribute_to_stix_pattern(&attr).unwrap();
        assert!(pattern.contains("SHA-256"));
    }

    #[test]
    fn test_attribute_to_stix_pattern_unknown() {
        let attr = MispAttribute::new("Other", "snort", "alert tcp");
        assert!(attribute_to_stix_pattern(&attr).is_none());
    }
}
