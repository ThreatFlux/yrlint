use std::io::{self, Write};
use std::path::PathBuf;
use yrlint::linter::{IssueSeverity, LintIssue, LintResults};
use yrlint::output;

// Helper function to create a test LintResults object
fn create_test_results() -> LintResults {
    let mut results = LintResults::new();
    results.files_count = 2;
    results.rules_count = 3;

    // Add a few test issues
    results.add_issue(LintIssue {
        rule_name: "test_rule1".to_string(),
        file_path: "test/file1.yar".to_string(),
        line: 10,
        severity: IssueSeverity::Error,
        code: "MISSING_REQUIRED_META".to_string(),
        message: "Missing required metadata field 'description'".to_string(),
        suggested_fix: Some("Fix suggestion".to_string()),
    });

    results.add_issue(LintIssue {
        rule_name: "test_rule2".to_string(),
        file_path: "test/file2.yar".to_string(),
        line: 5,
        severity: IssueSeverity::Warning,
        code: "SHORT_STRING".to_string(),
        message: "String is too short (2 bytes)".to_string(),
        suggested_fix: None,
    });

    results.add_issue(LintIssue {
        rule_name: "test_rule2".to_string(),
        file_path: "test/file2.yar".to_string(),
        line: 15,
        severity: IssueSeverity::Info,
        code: "INEFFICIENT_CONDITION_ORDER".to_string(),
        message: "Consider placing filesize check before string matching".to_string(),
        suggested_fix: None,
    });

    results
}

#[test]
fn test_text_output_format() {
    let results = create_test_results();

    // Redirect stdout to capture output
    let mut output = Vec::new();
    {
        output::print_results(&results, "text").unwrap();
    }

    // Convert captured output to string
    let output_str = String::from_utf8(output).unwrap_or_else(|_| "Invalid UTF-8".to_string());

    // Basic checks on the output format
    assert!(output_str.contains("Files scanned: 2"));
    assert!(output_str.contains("Rules checked: 3"));
    assert!(output_str.contains("Errors:   1"));
    assert!(output_str.contains("Warnings: 1"));
    assert!(output_str.contains("Info:     1"));

    // Check that issues are included
    assert!(output_str.contains("MISSING_REQUIRED_META"));
    assert!(output_str.contains("SHORT_STRING"));
    assert!(output_str.contains("INEFFICIENT_CONDITION_ORDER"));

    // Check suggested fix message
    assert!(output_str.contains("Suggested fix available"));
}

#[test]
fn test_json_output_format() {
    let results = create_test_results();

    // Redirect stdout to capture output
    let mut output = Vec::new();
    {
        output::print_results(&results, "json").unwrap();
    }

    // Convert captured output to string
    let output_str = String::from_utf8(output).unwrap_or_else(|_| "Invalid UTF-8".to_string());

    // Check that the output is valid JSON
    let json_value: serde_json::Value = serde_json::from_str(&output_str).unwrap();

    // Check summary fields
    assert_eq!(json_value["summary"]["files_scanned"], 2);
    assert_eq!(json_value["summary"]["rules_checked"], 3);
    assert_eq!(json_value["summary"]["error_count"], 1);
    assert_eq!(json_value["summary"]["warning_count"], 1);
    assert_eq!(json_value["summary"]["info_count"], 1);

    // Check that issues array has correct length
    assert_eq!(json_value["issues"].as_array().unwrap().len(), 3);

    // Check first issue details
    let first_issue = &json_value["issues"][0];
    assert_eq!(first_issue["rule_name"], "test_rule1");
    assert_eq!(first_issue["file_path"], "test/file1.yar");
    assert_eq!(first_issue["line"], 10);
    assert_eq!(first_issue["severity"], "error");
    assert_eq!(first_issue["code"], "MISSING_REQUIRED_META");
    assert_eq!(first_issue["has_suggested_fix"], true);
}

#[test]
fn test_github_output_format() {
    let results = create_test_results();

    // Redirect stdout to capture output
    let mut output = Vec::new();
    {
        output::print_results(&results, "github").unwrap();
    }

    // Convert captured output to string
    let output_str = String::from_utf8(output).unwrap_or_else(|_| "Invalid UTF-8".to_string());

    // Check GitHub Actions format
    assert!(
        output_str.contains("::error file=test/file1.yar,line=10,title=MISSING_REQUIRED_META::")
    );
    assert!(output_str.contains("::warning file=test/file2.yar,line=5,title=SHORT_STRING::"));
    assert!(output_str
        .contains("::notice file=test/file2.yar,line=15,title=INEFFICIENT_CONDITION_ORDER::"));

    // Check summary
    assert!(
        output_str.contains("::notice::YARA Linter found 1 errors, 1 warnings, and 1 info issues")
    );
}
