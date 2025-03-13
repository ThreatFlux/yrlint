use crate::config::Config;
use crate::linter::{IssueSeverity, LintIssue};
use crate::parser::Rule;

/// Check rule structure for YARA best practices
pub fn check(rule: &Rule, config: &Config) -> Vec<LintIssue> {
    let mut issues = Vec::new();

    // Check rule modifiers for YARA-X compatibility
    if config.enforce_yara_x {
        check_yara_x_compatibility(rule, &mut issues);
    }

    // Check for missing required sections
    check_required_sections(rule, &mut issues);

    // Check for balanced structures (this would be better done during parsing,
    // but we include it here for completeness)
    check_balanced_structure(rule, &mut issues);

    issues
}

/// Check rule modifiers for YARA-X compatibility
fn check_yara_x_compatibility(rule: &Rule, issues: &mut Vec<LintIssue>) {
    // Check for duplicate modifiers (not allowed in YARA-X)
    let source = &rule.source;

    if source.contains("private private") {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Error,
            code: "YARA_X_DUPLICATE_MODIFIER".to_string(),
            message: "YARA-X doesn't allow duplicate rule modifiers".to_string(),
            suggested_fix: Some(source.replace("private private", "private")),
        });
    }

    if source.contains("global global") {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Error,
            code: "YARA_X_DUPLICATE_MODIFIER".to_string(),
            message: "YARA-X doesn't allow duplicate rule modifiers".to_string(),
            suggested_fix: Some(source.replace("global global", "global")),
        });
    }

    // Check for negative array indices (not allowed in YARA-X)
    if source.contains("[-") {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Error,
            code: "YARA_X_NEGATIVE_INDEX".to_string(),
            message: "YARA-X doesn't allow negative array indices".to_string(),
            suggested_fix: None, // Would need to rewrite the array access logic
        });
    }

    // Check for base64 modifiers on strings less than 3 bytes
    for string in &rule.strings {
        if string.modifiers.contains(&"base64".to_string()) {
            // Extract actual string length (simplified)
            let value = &string.value;
            let clean_value = value.trim_matches('"');

            if clean_value.len() < 3 {
                issues.push(LintIssue {
                    rule_name: rule.name.clone(),
                    file_path: rule.source_file.display().to_string(),
                    line: rule.line_number,
                    severity: IssueSeverity::Error,
                    code: "YARA_X_BASE64_TOO_SHORT".to_string(),
                    message: format!(
                        "YARA-X requires base64 modifiers only on strings >= 3 bytes (found {})",
                        clean_value.len()
                    ),
                    suggested_fix: None, // Would need to modify the string or remove the modifier
                });
            }
        }
    }
}

/// Check for missing required sections
fn check_required_sections(rule: &Rule, issues: &mut Vec<LintIssue>) {
    // Condition section is required
    if rule.condition.is_empty() {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Error,
            code: "MISSING_CONDITION".to_string(),
            message: "Rule is missing required condition section".to_string(),
            suggested_fix: None, // Can't auto-fix missing condition
        });
    }

    // Check if a string is referenced in the condition but not defined
    for string_ref in &rule.string_refs {
        let exists = rule.strings.iter().any(|s| &s.identifier == string_ref);

        if !exists {
            issues.push(LintIssue {
                rule_name: rule.name.clone(),
                file_path: rule.source_file.display().to_string(),
                line: rule.line_number,
                severity: IssueSeverity::Error,
                code: "UNDEFINED_STRING".to_string(),
                message: format!(
                    "String '{}' is used in condition but not defined",
                    string_ref
                ),
                suggested_fix: None, // Can't auto-fix undefined strings
            });
        }
    }
}

/// Check for balanced structures (braces, parentheses)
fn check_balanced_structure(rule: &Rule, issues: &mut Vec<LintIssue>) {
    let source = &rule.source;

    // Check for balanced braces
    let open_braces = source.chars().filter(|&c| c == '{').count();
    let close_braces = source.chars().filter(|&c| c == '}').count();

    if open_braces != close_braces {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Error,
            code: "UNBALANCED_BRACES".to_string(),
            message: format!(
                "Rule has unbalanced braces: {} opening, {} closing",
                open_braces, close_braces
            ),
            suggested_fix: None, // Can't auto-fix unbalanced braces
        });
    }

    // Check for balanced parentheses
    let open_parens = source.chars().filter(|&c| c == '(').count();
    let close_parens = source.chars().filter(|&c| c == ')').count();

    if open_parens != close_parens {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Error,
            code: "UNBALANCED_PARENTHESES".to_string(),
            message: format!(
                "Rule has unbalanced parentheses: {} opening, {} closing",
                open_parens, close_parens
            ),
            suggested_fix: None, // Can't auto-fix unbalanced parentheses
        });
    }
}
