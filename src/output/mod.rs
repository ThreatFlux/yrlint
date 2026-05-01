use crate::linter::{IssueSeverity, LintResults};
use anyhow::{Context, Result};
use serde::Serialize;
use std::io::{self, Write};

/// Print lint results in the specified format.
pub fn print_results(results: &LintResults, format: &str) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    print_results_with_writer(results, format, &mut out)
}

/// Print lint results in the specified format to a custom writer.
pub fn print_results_with_writer<W: Write>(
    results: &LintResults,
    format: &str,
    out: &mut W,
) -> Result<()> {
    match format.to_lowercase().as_str() {
        "text" => print_text_format(results, out),
        "json" => print_json_format(results, out),
        "github" => print_github_format(results, out),
        _ => {
            writeln!(out, "Unknown output format: {}. Using text format.", format)?;
            print_text_format(results, out)
        }
    }
}

fn print_text_format<W: Write>(results: &LintResults, out: &mut W) -> Result<()> {
    writeln!(out, "YARA Rule Linting Results")?;
    writeln!(out, "=========================")?;
    writeln!(out)?;
    writeln!(out, "Files scanned: {}", results.files_count)?;
    writeln!(out, "Rules checked: {}", results.rules_count)?;
    writeln!(out, "Issues found:  {}", results.issues.len())?;
    writeln!(out, "  Errors:   {}", results.error_count)?;
    writeln!(out, "  Warnings: {}", results.warning_count)?;
    writeln!(out, "  Info:     {}", results.info_count)?;
    writeln!(out, "Issues fixed: {}", results.fixed_count)?;
    writeln!(out)?;

    if results.issues.is_empty() {
        writeln!(out, "No issues found!")?;
        return Ok(());
    }

    let mut issues_by_file = std::collections::HashMap::new();
    for issue in &results.issues {
        issues_by_file
            .entry(issue.file_path.clone())
            .or_insert_with(Vec::new)
            .push(issue);
    }

    for (file_path, issues) in &issues_by_file {
        writeln!(out, "File: {}", file_path)?;
        writeln!(out, "{}", "-".repeat(file_path.len() + 6))?;

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

                if issue.suggested_fix.is_some() {
                    writeln!(out, "      Suggested fix available")?;
                }
            }

            writeln!(out)?;
        }

        writeln!(out)?;
    }

    Ok(())
}

fn print_json_format<W: Write>(results: &LintResults, out: &mut W) -> Result<()> {
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
    writeln!(out, "{}", json)?;

    Ok(())
}

fn print_github_format<W: Write>(results: &LintResults, out: &mut W) -> Result<()> {
    for issue in &results.issues {
        let severity = match issue.severity {
            IssueSeverity::Error => "error",
            IssueSeverity::Warning => "warning",
            IssueSeverity::Info => "notice",
        };

        writeln!(
            out,
            "::{} file={},line={},title={}::{} [{}]",
            severity,
            issue.file_path,
            issue.line,
            issue.code,
            issue.message,
            issue.rule_name
        )?;
    }

    writeln!(
        out,
        "::notice::YARA Linter found {} errors, {} warnings, and {} info issues across {} rules in {} files.",
        results.error_count,
        results.warning_count,
        results.info_count,
        results.rules_count,
        results.files_count
    )?;

    Ok(())
}
