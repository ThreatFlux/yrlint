use crate::config::Config;
use crate::linter::{IssueSeverity, LintIssue};
use crate::parser::Rule;

/// Check rule metadata for required fields and formatting
pub fn check(rule: &Rule, config: &Config) -> Vec<LintIssue> {
    let mut issues = Vec::new();

    // Check for required metadata fields
    for field in &config.required_meta {
        if !rule.metadata.contains_key(field) {
            issues.push(LintIssue {
                rule_name: rule.name.clone(),
                file_path: rule.source_file.display().to_string(),
                line: rule.line_number,
                severity: IssueSeverity::Error,
                code: "MISSING_REQUIRED_META".to_string(),
                message: format!("Rule is missing required metadata field '{}'", field),
                suggested_fix: Some(add_metadata_field(rule, field)),
            });
        }
    }

    // Check for empty metadata values
    for (key, value) in &rule.metadata {
        if value.trim().is_empty() {
            issues.push(LintIssue {
                rule_name: rule.name.clone(),
                file_path: rule.source_file.display().to_string(),
                line: rule.line_number,
                severity: IssueSeverity::Warning,
                code: "EMPTY_META_VALUE".to_string(),
                message: format!("Metadata field '{}' has an empty value", key),
                suggested_fix: None,
            });
        }
    }

    // Check for metadata field name consistency
    // For example, if 'desc' is used instead of 'description'
    for (key, _) in &rule.metadata {
        if key == "desc" && !rule.metadata.contains_key("description") {
            issues.push(LintIssue {
                rule_name: rule.name.clone(),
                file_path: rule.source_file.display().to_string(),
                line: rule.line_number,
                severity: IssueSeverity::Warning,
                code: "INCONSISTENT_META_NAME".to_string(),
                message: "Use 'description' instead of 'desc' for consistency".to_string(),
                suggested_fix: Some(rename_metadata_field(rule, "desc", "description")),
            });
        }

        if key == "author_name" && !rule.metadata.contains_key("author") {
            issues.push(LintIssue {
                rule_name: rule.name.clone(),
                file_path: rule.source_file.display().to_string(),
                line: rule.line_number,
                severity: IssueSeverity::Warning,
                code: "INCONSISTENT_META_NAME".to_string(),
                message: "Use 'author' instead of 'author_name' for consistency".to_string(),
                suggested_fix: Some(rename_metadata_field(rule, "author_name", "author")),
            });
        }

        if key == "created" && !rule.metadata.contains_key("date") {
            issues.push(LintIssue {
                rule_name: rule.name.clone(),
                file_path: rule.source_file.display().to_string(),
                line: rule.line_number,
                severity: IssueSeverity::Warning,
                code: "INCONSISTENT_META_NAME".to_string(),
                message: "Use 'date' instead of 'created' for consistency".to_string(),
                suggested_fix: Some(rename_metadata_field(rule, "created", "date")),
            });
        }
    }

    issues
}

/// Generate a fix for adding a missing metadata field
fn add_metadata_field(rule: &Rule, field: &str) -> String {
    // Check if the rule has a metadata section
    if rule.metadata.is_empty() {
        // No metadata section, add a new one
        let meta_section = format!(
            "rule {} {{\n    meta:\n        {} = \"\"\n",
            rule.name, field
        );

        // This is a simplified approach, a real implementation would need to be more careful
        // about maintaining the original rule structure
        let rule_source = rule.source.clone();
        rule_source.replace(&format!("rule {} {{", rule.name), &meta_section)
    } else {
        // Metadata section exists, add the field
        // This is a simplified approach, a real implementation would need to be more careful
        let meta_line = format!("        {} = \"\"", field);

        // Find the metadata section and add the field
        let rule_source = rule.source.clone();
        if let Some(meta_idx) = rule_source.find("meta:") {
            let (before, after) = rule_source.split_at(meta_idx + 6);
            format!("{}\n{}{}", before, meta_line, after)
        } else {
            // This should not happen if metadata is not empty
            rule_source
        }
    }
}

/// Generate a fix for renaming a metadata field
fn rename_metadata_field(rule: &Rule, old_name: &str, new_name: &str) -> String {
    let rule_source = rule.source.clone();

    // This is a simplified approach, a real implementation would need to be more careful
    if let Some(old_field_str) = rule.metadata.get(old_name) {
        rule_source.replace(
            &format!("{} = {}", old_name, old_field_str),
            &format!("{} = {}", new_name, old_field_str),
        )
    } else {
        rule_source
    }
}
