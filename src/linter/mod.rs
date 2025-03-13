mod rules;

use crate::config::Config;
use crate::parser::{parse_file, Rule};
use anyhow::{Context, Result};
use log::{debug, info};
use rules::{check_condition, check_metadata, check_naming, check_strings, check_structure};
use std::fs;
use std::path::Path;

/// Represents a lint issue found in a YARA rule
#[derive(Debug, Clone)]
pub struct LintIssue {
    /// Rule name
    pub rule_name: String,

    /// Source file path
    pub file_path: String,

    /// Line number in the source file
    pub line: usize,

    /// Issue severity (error, warning, info)
    pub severity: IssueSeverity,

    /// Issue code (for categorization)
    pub code: String,

    /// Issue message
    pub message: String,

    /// Suggested fix (if available)
    pub suggested_fix: Option<String>,
}

/// Severity of a lint issue
#[derive(Debug, Clone, PartialEq)]
pub enum IssueSeverity {
    Error,
    Warning,
    Info,
}

/// Results of linting a set of YARA rule files
#[derive(Debug)]
pub struct LintResults {
    /// Lint issues found
    pub issues: Vec<LintIssue>,

    /// Number of files linted
    pub files_count: usize,

    /// Number of rules linted
    pub rules_count: usize,

    /// Number of errors found
    pub error_count: usize,

    /// Number of warnings found
    pub warning_count: usize,

    /// Number of informational issues found
    pub info_count: usize,

    /// Number of fixes applied
    pub fixed_count: usize,
}

impl LintResults {
    /// Create a new empty LintResults
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
            files_count: 0,
            rules_count: 0,
            error_count: 0,
            warning_count: 0,
            info_count: 0,
            fixed_count: 0,
        }
    }

    /// Add a lint issue to the results
    pub fn add_issue(&mut self, issue: LintIssue) {
        match issue.severity {
            IssueSeverity::Error => self.error_count += 1,
            IssueSeverity::Warning => self.warning_count += 1,
            IssueSeverity::Info => self.info_count += 1,
        }
        self.issues.push(issue);
    }

    /// Check if there are any errors in the results
    pub fn has_errors(&self) -> bool {
        self.error_count > 0
    }

    /// Increment the fixed count
    pub fn increment_fixed(&mut self) {
        self.fixed_count += 1;
    }
}

/// Lint a set of YARA rule files
pub fn lint_files<P: AsRef<Path>>(files: &[P], config: &Config, fix: bool) -> Result<LintResults> {
    let mut results = LintResults::new();
    results.files_count = files.len();

    for file in files {
        let file_path = file.as_ref();
        debug!("Linting file: {}", file_path.display());

        // Parse the YARA rule file
        let rules = match parse_file(file_path) {
            Ok(rules) => rules,
            Err(e) => {
                let issue = LintIssue {
                    rule_name: String::new(),
                    file_path: file_path.display().to_string(),
                    line: 0,
                    severity: IssueSeverity::Error,
                    code: "PARSE_ERROR".to_string(),
                    message: format!("Failed to parse YARA rule file: {}", e),
                    suggested_fix: None,
                };
                results.add_issue(issue);
                continue;
            }
        };

        results.rules_count += rules.len();

        // Lint each rule in the file
        let file_issues = lint_rules(&rules, config);

        // Add issues to results
        for issue in &file_issues {
            results.add_issue(issue.clone());
        }

        // Apply fixes if requested
        if fix && !file_issues.is_empty() {
            apply_fixes(file_path, &rules, &file_issues, &mut results)?;
        }
    }

    info!(
        "Lint results: {} files, {} rules, {} errors, {} warnings, {} info, {} fixed",
        results.files_count,
        results.rules_count,
        results.error_count,
        results.warning_count,
        results.info_count,
        results.fixed_count
    );

    Ok(results)
}

/// Lint a set of YARA rules
fn lint_rules(rules: &[Rule], config: &Config) -> Vec<LintIssue> {
    let mut issues = Vec::new();

    for rule in rules {
        // Check rule structure
        let mut structure_issues = check_structure::check(rule, config);
        issues.append(&mut structure_issues);

        // Check rule metadata
        let mut metadata_issues = check_metadata::check(rule, config);
        issues.append(&mut metadata_issues);

        // Check rule naming
        let mut naming_issues = check_naming::check(rule, config);
        issues.append(&mut naming_issues);

        // Check rule strings
        let mut string_issues = check_strings::check(rule, config);
        issues.append(&mut string_issues);

        // Check rule condition
        let mut condition_issues = check_condition::check(rule, config);
        issues.append(&mut condition_issues);
    }

    // Check for cross-rule issues
    if config.check_cross_rule_duplicates {
        // Add cross-rule duplication checks
        // This is a placeholder - actual implementation would compare strings across rules
    }

    issues
}

/// Apply fixes to a YARA rule file
fn apply_fixes<P: AsRef<Path>>(
    file_path: P,
    rules: &[Rule],
    issues: &[LintIssue],
    results: &mut LintResults,
) -> Result<()> {
    let file_path = file_path.as_ref();

    // Only apply fixes if there are fixable issues
    let fixable_issues: Vec<_> = issues
        .iter()
        .filter(|issue| issue.suggested_fix.is_some())
        .collect();

    if fixable_issues.is_empty() {
        return Ok(());
    }

    // Read the file content
    let content = fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read file for fixing: {}", file_path.display()))?;

    // Apply fixes one by one (this is a simplified approach)
    // A more robust implementation would parse the AST, modify it, and regenerate the source
    let mut modified_content = content.clone();

    for issue in fixable_issues {
        if let Some(fix) = &issue.suggested_fix {
            // This is a very naive approach - just a placeholder
            // Real implementation would do more careful text manipulation or AST-based changes
            let rule = rules.iter().find(|r| r.name == issue.rule_name).unwrap();
            if modified_content.contains(&rule.source) {
                modified_content = modified_content.replace(&rule.source, fix);
                results.increment_fixed();
            }
        }
    }

    // Write the modified content back to the file
    if modified_content != content {
        fs::write(file_path, modified_content).with_context(|| {
            format!(
                "Failed to write fixed content to file: {}",
                file_path.display()
            )
        })?;

        info!("Applied fixes to file: {}", file_path.display());
    }

    Ok(())
}
