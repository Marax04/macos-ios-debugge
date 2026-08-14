//! Import `IoCs` from CSV lists into MISP events.

use crate::error::MispError;
use crate::models::{MispAnalysis, MispAttribute, MispDistribution, MispEvent, MispThreatLevel};

/// # Errors
///
/// Returns an error if the operation fails.
/// Parse a CSV `IoC` list into a `MispEvent`.
///
/// Expected CSV format (no header):
/// ```text
/// <type>,<value>[,<comment>]
/// ```
/// Where `<type>` is a MISP attribute type such as `ip-dst`, `sha256`, `domain`, etc.
///
/// Lines beginning with `#` are ignored.
pub fn import_csv(csv: &str, event_info: &str) -> Result<MispEvent, MispError> {
    let mut event = MispEvent::new(
        event_info,
        MispThreatLevel::Undefined,
        MispAnalysis::Initial,
        MispDistribution::Organization,
    );

    for (line_no, line) in csv.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(3, ',').collect();
        if parts.len() < 2 {
            return Err(MispError::invalid_input(format!(
                "line {}: expected at least 2 comma-separated fields, got: {}",
                line_no + 1,
                trimmed
            )));
        }

        let attr_type = parts[0].trim();
        let value = parts[1].trim();
        let comment = parts.get(2).copied().unwrap_or("").trim().to_string();

        let (category, to_ids) = category_for_type(attr_type);

        let attr = MispAttribute {
            id: None,
            event_id: None,
            category: category.to_string(),
            ty: attr_type.to_string(),
            value: value.to_string(),
            to_ids,
            comment,
            tags: Vec::new(),
        };

        event.add_attribute(attr);
    }

    Ok(event)
}

/// Determine the MISP attribute category and `to_ids` flag from a type string.
fn category_for_type(attr_type: &str) -> (&'static str, bool) {
    match attr_type {
        "ip-dst" | "ip-src" => ("Network activity", true),
        "domain" | "hostname" => ("Network activity", true),
        "url" => ("Network activity", true),
        "md5" | "sha1" | "sha256" | "sha512" | "imphash" | "ssdeep" => ("Payload delivery", true),
        "filename" => ("Payload delivery", false),
        "email-src" | "email-dst" => ("Email", true),
        "registry-key" | "mutex" => ("Artifacts dropped", true),
        "yara" => ("Other", false),
        _ => ("Other", false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CSV: &str = r"
# This is a comment
ip-dst,192.168.1.100,C2 server
sha256,e3b0c44298fc1c149afbf4c8996fb924,empty file hash
domain,evil.example.com
url,http://evil.example.com/payload,Download URL
md5,d41d8cd98f00b204e9800998ecf8427e
";

    #[test]
    fn test_import_csv_basic() {
        let event = import_csv(SAMPLE_CSV, "Test Import").unwrap();
        assert_eq!(event.info, "Test Import");
        assert_eq!(event.attributes.len(), 5);
    }

    #[test]
    fn test_import_csv_comments_skipped() {
        let csv = "# comment\nip-dst,1.2.3.4";
        let event = import_csv(csv, "test").unwrap();
        assert_eq!(event.attributes.len(), 1);
    }

    #[test]
    fn test_import_csv_to_ids_network() {
        let event = import_csv("ip-dst,1.2.3.4", "test").unwrap();
        assert!(event.attributes[0].to_ids);
        assert_eq!(event.attributes[0].category, "Network activity");
    }

    #[test]
    fn test_import_csv_to_ids_hash() {
        let event = import_csv("sha256,abc123", "test").unwrap();
        assert!(event.attributes[0].to_ids);
        assert_eq!(event.attributes[0].category, "Payload delivery");
    }

    #[test]
    fn test_import_csv_comment_field() {
        let event = import_csv("ip-dst,10.0.0.1,My comment here", "test").unwrap();
        assert_eq!(event.attributes[0].comment, "My comment here");
    }

    #[test]
    fn test_import_csv_invalid_line() {
        let result = import_csv("onlyonefield", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_import_csv_empty_lines_skipped() {
        let csv = "\n\nip-dst,1.2.3.4\n\n";
        let event = import_csv(csv, "test").unwrap();
        assert_eq!(event.attributes.len(), 1);
    }
}
