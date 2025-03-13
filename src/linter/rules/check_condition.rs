use crate::config::Config;
use crate::linter::{IssueSeverity, LintIssue};
use crate::parser::Rule;
use regex::Regex;

/// Check rule condition for performance and correctness
pub fn check(rule: &Rule, config: &Config) -> Vec<LintIssue> {
    let mut issues = Vec::new();

    // Get the condition string
    let condition = &rule.condition;

    // Check for loops with large iteration ranges
    if config.warn_large_loops {
        check_large_loops(rule, condition, config, &mut issues);
    }

    // Check condition order (filesize and cheap checks should come first)
    if config.check_condition_order {
        check_condition_order(rule, condition, &mut issues);
    }

    // Check for rule complexity
    if config.check_rule_complexity {
        check_rule_complexity(rule, condition, config, &mut issues);
    }

    // Check for used modules and if they're allowed
    check_allowed_modules(rule, config, &mut issues);

    // Check for files that don't use their imports
    check_unused_imports(rule, &mut issues);

    issues
}

/// Check for loops with large iteration ranges
fn check_large_loops(rule: &Rule, condition: &str, config: &Config, issues: &mut Vec<LintIssue>) {
    // Look for for-loops with filesize or large constant as bound
    let loop_pattern = Regex::new(r"for\s+\w+\s+in\s+\(.*?filesize").unwrap();

    if loop_pattern.is_match(condition) {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Warning,
            code: "LARGE_LOOP_RANGE".to_string(),
            message: "Loop iterates over filesize range, which may be very inefficient".to_string(),
            suggested_fix: None, // No automatic fix, need more context
        });
    }

    // Also check for large numeric constants in loop bounds
    let large_constant_pattern = Regex::new(r"for\s+\w+\s+in\s+\(\d+\s*\.\.\s*(\d+)").unwrap();

    if let Some(captures) = large_constant_pattern.captures(condition) {
        if let Some(bound) = captures.get(1) {
            if let Ok(value) = bound.as_str().parse::<usize>() {
                if value > config.loop_max_size {
                    issues.push(LintIssue {
                        rule_name: rule.name.clone(),
                        file_path: rule.source_file.display().to_string(),
                        line: rule.line_number,
                        severity: IssueSeverity::Warning,
                        code: "LARGE_LOOP_CONSTANT".to_string(),
                        message: format!(
                            "Loop uses a large upper bound: {} (max recommended: {})",
                            value, config.loop_max_size
                        ),
                        suggested_fix: None, // No automatic fix, need more context
                    });
                }
            }
        }
    }
}

/// Check condition order (filesize and cheap checks should come first)
fn check_condition_order(rule: &Rule, condition: &str, issues: &mut Vec<LintIssue>) {
    // Check if the condition contains filesize check
    let has_filesize = condition.contains("filesize");

    // Check if it has string checks
    let has_strings = rule
        .strings
        .iter()
        .any(|s| condition.contains(&s.identifier));

    // Check if the filesize check is first in an AND condition
    if has_filesize && has_strings {
        // This is a simplified approach - in reality we'd need to parse the condition AST
        // to accurately determine the order of operations

        // Check for patterns like "string_check and filesize < X" (string check before filesize)
        let string_then_filesize = rule.strings.iter().any(|s| {
            let pattern = format!(r"{}\s+and\s+filesize", s.identifier);
            Regex::new(&pattern).unwrap().is_match(condition)
        });

        if string_then_filesize {
            issues.push(LintIssue {
                rule_name: rule.name.clone(),
                file_path: rule.source_file.display().to_string(),
                line: rule.line_number,
                severity: IssueSeverity::Info,
                code: "INEFFICIENT_CONDITION_ORDER".to_string(),
                message:
                    "Consider putting filesize checks before string checks for better performance"
                        .to_string(),
                suggested_fix: None, // No automatic fix, would need to rewrite the condition
            });
        }
    }

    // Check for file type checks (magic headers)
    let has_file_header_check = condition.contains("uint32(0)") || condition.contains("uint16(0)");

    // If we have a file header check but it's not at the beginning of the condition
    if has_file_header_check && !condition.starts_with("uint") {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Info,
            code: "HEADER_CHECK_NOT_FIRST".to_string(),
            message:
                "Consider putting file header checks first in the condition for better performance"
                    .to_string(),
            suggested_fix: None, // No automatic fix, would need to rewrite the condition
        });
    }
}

/// Check for rule complexity (condition depth/size)
fn check_rule_complexity(
    rule: &Rule,
    condition: &str,
    config: &Config,
    issues: &mut Vec<LintIssue>,
) {
    // Count nesting level by counting parentheses depth
    let mut max_depth: usize = 0;
    let mut current_depth: usize = 0;

    for c in condition.chars() {
        if c == '(' {
            current_depth += 1;
            max_depth = max_depth.max(current_depth);
        } else if c == ')' {
            current_depth = current_depth.saturating_sub(1);
        }
    }

    if max_depth > config.max_condition_depth {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Warning,
            code: "CONDITION_TOO_COMPLEX".to_string(),
            message: format!(
                "Condition is too complex with nesting depth of {} (max {})",
                max_depth, config.max_condition_depth
            ),
            suggested_fix: None, // No automatic fix, would need to simplify the condition
        });
    }

    // Check condition length (rough approximation of complexity)
    let condition_length = condition.len();
    if condition_length > 500 {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Info,
            code: "CONDITION_TOO_LONG".to_string(),
            message: format!(
                "Condition is very long ({} characters), consider simplifying",
                condition_length
            ),
            suggested_fix: None, // No automatic fix, would need to simplify the condition
        });
    }
}

/// Check for used modules and if they're allowed
fn check_allowed_modules(rule: &Rule, config: &Config, issues: &mut Vec<LintIssue>) {
    for module in &rule.modules {
        if !config.allowed_modules.contains(module) {
            issues.push(LintIssue {
                rule_name: rule.name.clone(),
                file_path: rule.source_file.display().to_string(),
                line: rule.line_number,
                severity: IssueSeverity::Warning,
                code: "DISALLOWED_MODULE".to_string(),
                message: format!("Rule uses disallowed module '{}'", module),
                suggested_fix: None, // No automatic fix, would need to rewrite the condition
            });
        }
    }

    // Check for unnecessary module usage (e.g., using pe module just for header check)
    let condition = &rule.condition;

    if rule.modules.contains(&"pe".to_string()) && condition.contains("pe.is_pe") {
        // Suggest using uint32(0) instead of pe.is_pe
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Info,
            code: "UNNECESSARY_MODULE_USE".to_string(),
            message:
                "Consider using 'uint32(0) == 0x5A4D' instead of 'pe.is_pe' for better performance"
                    .to_string(),
            suggested_fix: None, // No automatic fix, would need to rewrite the condition
        });
    }
}

/// Check for rules that don't use their imports
fn check_unused_imports(rule: &Rule, issues: &mut Vec<LintIssue>) {
    // This is a simplified placeholder - in a real implementation, we would need to
    // analyze the AST to accurately detect imported modules that aren't used

    // Example check: if the rule has an 'import pe' but doesn't use 'pe.' in the condition
    if rule.source.contains("import pe") && !rule.condition.contains("pe.") {
        issues.push(LintIssue {
            rule_name: rule.name.clone(),
            file_path: rule.source_file.display().to_string(),
            line: rule.line_number,
            severity: IssueSeverity::Warning,
            code: "UNUSED_IMPORT".to_string(),
            message: "Rule imports 'pe' module but doesn't use it in the condition".to_string(),
            suggested_fix: None, // Would need to remove the import
        });
    }
}
