use crate::config::Config;
use crate::linter::{IssueSeverity, LintIssue};
use crate::parser::{Rule, StringType};
use regex::Regex;

/// Check rule strings for performance and best practices
pub fn check(rule: &Rule, config: &Config) -> Vec<LintIssue> {
    let mut issues = Vec::new();

    // Check for too many strings
    if rule.strings.len() > config.max_strings_per_rule {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Warning,
            code: "TOO_MANY_STRINGS".to_string(),
            message: format!(
                "Rule has too many strings: {} (max {})",
                rule.strings.len(),
                config.max_strings_per_rule
            ),
            suggested_fix: None, // No automatic fix, would need to split the rule
        });
    }

    // Check for unused strings (defined but not used in condition)
    if config.warn_unused_strings {
        for string in &rule.strings {
            if !string.is_private && !rule.string_refs.contains(&string.identifier) {
                issues.push(LintIssue {
                    rule_name: rule.name.clone(),
                    file_path: rule.source_file.display().to_string(),
                    line: rule.line_number,
                    severity: IssueSeverity::Warning,
                    code: "UNUSED_STRING".to_string(),
                    message: format!(
                        "String '{}' is defined but not used in the condition",
                        string.identifier
                    ),
                    suggested_fix: Some(make_string_private(rule, &string.identifier)),
                });
            }
        }
    }

    // Check string length and content
    for string in &rule.strings {
        // Check for short text strings
        if string.string_type == StringType::Text {
            let value = &string.value;
            // Remove quotes if present
            let clean_value = value.trim_matches('"');

            if clean_value.len() < config.min_atom_length {
                issues.push(LintIssue {
                    rule_name: rule.name.clone(),
                    file_path: rule.source_file.display().to_string(),
                    line: rule.line_number,
                    severity: IssueSeverity::Warning,
                    code: "SHORT_STRING".to_string(),
                    message: format!(
                        "String '{}' is too short: {} bytes (min {})",
                        string.identifier,
                        clean_value.len(),
                        config.min_atom_length
                    ),
                    suggested_fix: None, // No automatic fix, need more context
                });
            }

            // Check for nocase on short strings (could be inefficient)
            if clean_value.len() < 6 && string.modifiers.contains(&"nocase".to_string()) {
                issues.push(LintIssue {
                    rule_name: rule.name.clone(),
                    file_path: rule.source_file.display().to_string(),
                    line: rule.line_number,
                    severity: IssueSeverity::Info,
                    code: "NOCASE_ON_SHORT_STRING".to_string(),
                    message: format!(
                        "Using 'nocase' on short string '{}' may be inefficient",
                        string.identifier
                    ),
                    suggested_fix: None, // No automatic fix, need more context
                });
            }

            // Check for repeated bytes (like "AAAA")
            if clean_value.len() >= 3 {
                let first_char = clean_value.chars().next().unwrap();
                if clean_value.chars().all(|c| c == first_char) {
                    issues.push(LintIssue {
                        rule_name: rule.name.clone(),
                        file_path: rule.source_file.display().to_string(),
                        line: rule.line_number,
                        severity: IssueSeverity::Warning,
                        code: "REPEATED_BYTES".to_string(),
                        message: format!(
                            "String '{}' contains only repeated bytes and may match too frequently",
                            string.identifier
                        ),
                        suggested_fix: None, // No automatic fix, need more context
                    });
                }
            }
        }

        // Check for inefficient regex patterns
        if string.string_type == StringType::Regex {
            let value = &string.value;

            // Check for forbidden patterns
            for forbidden in &config.forbid_patterns {
                if value.contains(forbidden) {
                    issues.push(LintIssue {
                        rule_name: rule.name.clone(),
                        file_path: rule.source_file.display().to_string(),
                        line: rule.line_number,
                        severity: IssueSeverity::Warning,
                        code: "FORBIDDEN_REGEX_PATTERN".to_string(),
                        message: format!(
                            "String '{}' contains forbidden regex pattern: {}",
                            string.identifier, forbidden
                        ),
                        suggested_fix: None, // No automatic fix, need more context
                    });
                }
            }

            // Check for unbounded quantifiers
            let unbounded_pattern = Regex::new(r"\.\*|\.\+|\{[0-9]+,\}").unwrap();
            if unbounded_pattern.is_match(value) {
                issues.push(LintIssue {
                    rule_name: rule.name.clone(),
                    file_path: rule.source_file.display().to_string(),
                    line: rule.line_number,
                    severity: IssueSeverity::Warning,
                    code: "UNBOUNDED_REGEX".to_string(),
                    message: format!(
                        "String '{}' contains unbounded regex quantifiers which may cause excessive backtracking",
                        string.identifier
                    ),
                    suggested_fix: None, // No automatic fix, need more context
                });
            }

            // Check for regex with no literal segment
            let has_literal = Regex::new(r"[a-zA-Z0-9_]{4,}").unwrap();
            if !has_literal.is_match(value) {
                issues.push(LintIssue {
                    rule_name: rule.name.clone(),
                    file_path: rule.source_file.display().to_string(),
                    line: rule.line_number,
                    severity: IssueSeverity::Info,
                    code: "NO_LITERAL_IN_REGEX".to_string(),
                    message: format!(
                        "String '{}' does not contain a literal segment of 4+ characters for efficient matching",
                        string.identifier
                    ),
                    suggested_fix: None, // No automatic fix, need more context
                });
            }
        }

        // Check for hex strings with too many wildcards
        if string.string_type == StringType::Hex {
            let value = &string.value;

            // Count wildcards (?) in hex pattern (simplified approach)
            let wildcard_count = value.chars().filter(|&c| c == '?').count();
            let total_length = value.len();

            if total_length > 0 && (wildcard_count as f64 / total_length as f64) > 0.5 {
                issues.push(LintIssue {
                    rule_name: rule.name.clone(),
                    file_path: rule.source_file.display().to_string(),
                    line: rule.line_number,
                    severity: IssueSeverity::Warning,
                    code: "TOO_MANY_WILDCARDS".to_string(),
                    message: format!(
                        "Hex string '{}' has too many wildcards (>50%), consider adding more specific bytes",
                        string.identifier
                    ),
                    suggested_fix: None, // No automatic fix, need more context
                });
            }

            // Check for long sequences of wildcards
            if value.contains("??????????") {
                // 5+ consecutive wildcards (10 ? chars)
                issues.push(LintIssue {
                    rule_name: rule.name.clone(),
                    file_path: rule.source_file.display().to_string(),
                    line: rule.line_number,
                    severity: IssueSeverity::Warning,
                    code: "LONG_WILDCARD_SEQUENCE".to_string(),
                    message: format!(
                        "Hex string '{}' contains a long sequence of wildcards, consider adding more specific bytes",
                        string.identifier
                    ),
                    suggested_fix: None, // No automatic fix, need more context
                });
            }
        }
    }

    issues
}

/// Generate a fix to make an unused string private by adding an underscore prefix
fn make_string_private(rule: &Rule, string_id: &str) -> String {
    let rule_source = rule.source.clone();

    // This is a simplified approach, a real implementation would need to be more careful
    rule_source.replace(&format!("${}", string_id), &format!("$_{}", string_id))
}
