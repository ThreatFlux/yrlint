use crate::linter::{IssueSeverity, LintResults};
use anyhow::{Context, Result};
use serde::Serialize;
use std::io::{self, Write};

/// Print lint results in the specified format
pub fn print_results(results: &LintResults, format: &str) -> Result<()> {
    match format.to_lowercase().as_str() {
        "text" => print_text_format(results),
        "json" => print_json_format(results),
        "github" => print_github_format(results),
        _ => {
            eprintln!("Unknown output format: {}. Using text format.", format);
            print_text_format(results)
        }
    }
}

/// Print results in plain text format
fn print_text_format(results: &LintResults) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    writeln!(out, "YARA Rule Linting Results")?;
    writeln!(out, "=========================")?;
    writeln!(out, "")?;
    writeln!(out, "Files scanned: {}", results.files_count)?;
    writeln!(out, "Rules checked: {}", results.rules_count)?;
    writeln!(out, "Issues found:  {}", results.issues.len())?;
    writeln!(out, "  Errors:   {}", results.error_count)?;
    writeln!(out, "  Warnings: {}", results.warning_count)?;
    writeln!(out, "  Info:     {}", results.info_count)?;
    writeln!(out, "Issues fixed: {}", results.fixed_count)?;
    writeln!(out, "")?;

    if results.issues.is_empty() {
        writeln!(out, "No issues found!")?;
        return Ok(());
    }

    // Group issues by file
    let mut issues_by_file = std::collections::HashMap::new();
    for issue in &results.issues {
        issues_by_file
            .entry(issue.file_path.clone())
            .or_insert_with(Vec::new)
            .push(issue);
    }

    // Print issues grouped by file
    for (file_path, issues) in &issues_by_file {
        writeln!(out, "File: {}", file_path)?;
        writeln!(out, "{}", "-".repeat(file_path.len() + 6))?;

        // Group issues by rule
        let mut issues_by_rule = std::collections::HashMap::new();
        for issue in issues {
            issues_by_rule
                .entry(issue.rule_name.clone())
                .or_insert_with(Vec::new)
                .push(issue);
        }

        for (rule_name, rule_issues) in &issues_by_rule {
            writeln!(out, "  Rule: {}", rule_name)?;

            for issue in rule_issues {
                let severity = match issue.severity {
                    IssueSeverity::Error => "ERROR",
                    IssueSeverity::Warning => "WARNING",
                    IssueSeverity::Info => "INFO",
                };

                writeln!(out, "    [{}] {} ({})", severity, issue.message, issue.code)?;

                if let Some(_fix) = &issue.suggested_fix {
                    writeln!(out, "      Suggested fix available")?;
                }
            }

            writeln!(out)?;
        }

        writeln!(out)?;
    }

    Ok(())
}

/// Print results in JSON format
fn print_json_format(results: &LintResults) -> Result<()> {
    #[derive(Serialize)]
    struct JsonOutput {
        summary: Summary,
        issues: Vec<JsonIssue>,
    }

    #[derive(Serialize)]
    struct Summary {
        files_scanned: usize,
        rules_checked: usize,
        error_count: usize,
        warning_count: usize,
        info_count: usize,
        fixed_count: usize,
    }

    #[derive(Serialize)]
    struct JsonIssue {
        rule_name: String,
        file_path: String,
        line: usize,
        severity: String,
        code: String,
        message: String,
        has_suggested_fix: bool,
    }

    let summary = Summary {
        files_scanned: results.files_count,
        rules_checked: results.rules_count,
        error_count: results.error_count,
        warning_count: results.warning_count,
        info_count: results.info_count,
        fixed_count: results.fixed_count,
    };

    let issues: Vec<JsonIssue> = results
        .issues
        .iter()
        .map(|issue| JsonIssue {
            rule_name: issue.rule_name.clone(),
            file_path: issue.file_path.clone(),
            line: issue.line,
            severity: match issue.severity {
                IssueSeverity::Error => "error".to_string(),
                IssueSeverity::Warning => "warning".to_string(),
                IssueSeverity::Info => "info".to_string(),
            },
            code: issue.code.clone(),
            message: issue.message.clone(),
            has_suggested_fix: issue.suggested_fix.is_some(),
        })
        .collect();

    let output = JsonOutput { summary, issues };
    let json = serde_json::to_string_pretty(&output).context("Failed to serialize JSON output")?;

    println!("{}", json);

    Ok(())
}

/// Print results in GitHub Actions format
fn print_github_format(results: &LintResults) -> Result<()> {
    for issue in &results.issues {
        let severity = match issue.severity {
            IssueSeverity::Error => "error",
            IssueSeverity::Warning => "warning",
            IssueSeverity::Info => "notice",
        };

        // Format: ::error file={name},line={line},title={title}::{message}
        println!(
            "::{}file={},line={},title={}::{} [{}]",
            severity, issue.file_path, issue.line, issue.code, issue.message, issue.rule_name
        );
    }

    // Print a summary
    println!("::notice::YARA Linter found {} errors, {} warnings, and {} info issues across {} rules in {} files.",
             results.error_count,
             results.warning_count,
             results.info_count,
             results.rules_count,
             results.files_count);

    Ok(())
}
