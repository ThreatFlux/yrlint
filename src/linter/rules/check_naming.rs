use crate::config::Config;
use crate::linter::{IssueSeverity, LintIssue};
use crate::parser::Rule;
use regex::Regex;

/// Check rule naming for conventions and length
pub fn check(rule: &Rule, config: &Config) -> Vec<LintIssue> {
    let mut issues = Vec::new();

    // Check rule name length
    if rule.name.len() > config.max_rule_name_length {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Warning,
            code: "RULE_NAME_TOO_LONG".to_string(),
            message: format!(
                "Rule name is too long: {} characters (max {})",
                rule.name.len(),
                config.max_rule_name_length
            ),
            suggested_fix: None, // No automatic fix for this
        });
    }

    // Check rule name pattern if configured
    if let Some(pattern) = &config.name_pattern {
        if let Ok(regex) = Regex::new(pattern) {
            if !regex.is_match(&rule.name) {
                issues.push(LintIssue {
                    rule_name: rule.name.clone(),
                    file_path: rule.source_file.display().to_string(),
                    line: rule.line_number,
                    severity: IssueSeverity::Warning,
                    code: "RULE_NAME_PATTERN".to_string(),
                    message: format!("Rule name does not match required pattern: {}", pattern),
                    suggested_fix: None, // No automatic fix for this
                });
            }
        }
    }

    // Check for non-descriptive names (e.g., too short, no vowels)
    if rule.name.len() < 5 {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Info,
            code: "RULE_NAME_TOO_SHORT".to_string(),
            message: "Rule name is too short, consider using a more descriptive name".to_string(),
            suggested_fix: None, // No automatic fix for this
        });
    }

    // Check if the name has no vowels (might be a non-descriptive name)
    if !rule
        .name
        .to_lowercase()
        .chars()
        .any(|c| "aeiou".contains(c))
        && rule.name.len() > 3
    {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Info,
            code: "RULE_NAME_NO_VOWELS".to_string(),
            message: "Rule name has no vowels, consider using a more readable name".to_string(),
            suggested_fix: None, // No automatic fix for this
        });
    }

    // Check if the name uses common naming convention (Type_Family_Detail)
    if !rule.name.contains('_') {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Info,
            code: "RULE_NAME_NO_SEPARATOR".to_string(),
            message: "Consider using underscores to separate parts of the rule name (e.g., Type_Family_Detail)".to_string(),
            suggested_fix: None, // No automatic fix for this
        });
    }

    issues
}
