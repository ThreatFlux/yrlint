use std::fs;
use std::path::Path;
use tempfile::tempdir;
use yrlint::config::Config;
use yrlint::linter::{lint_files, IssueSeverity};
use yrlint::parser::Rule;

#[test]
fn test_lint_good_rule() {
    let config = Config::default();
    let path = Path::new("examples/good_rule.yar");

    // Skip test if the example file doesn't exist
    if !path.exists() {
        return;
    }

    let results = lint_files(&[path], &config, false).unwrap();

    // Good rule should have minimal issues
    let error_count = results
        .issues
        .iter()
        .filter(|i| i.severity == IssueSeverity::Error)
        .count();

    assert_eq!(error_count, 0, "Good rule should have no errors");
}

#[test]
fn test_lint_bad_rule() {
    let config = Config::default();
    let path = Path::new("examples/bad_rule.yar");

    // Skip test if the example file doesn't exist
    if !path.exists() {
        return;
    }

    let results = lint_files(&[path], &config, false).unwrap();

    // Bad rule should have multiple issues
    assert!(results.issues.len() > 0, "Bad rule should have issues");

    // Check for specific issues
    let has_short_string_issue = results.issues.iter().any(|i| i.code == "SHORT_STRING");

    let has_forbidden_regex_issue = results
        .issues
        .iter()
        .any(|i| i.code == "FORBIDDEN_REGEX_PATTERN");

    let has_unused_string_issue = results.issues.iter().any(|i| i.code == "UNUSED_STRING");

    assert!(has_short_string_issue, "Should detect short string issue");
    assert!(
        has_forbidden_regex_issue,
        "Should detect forbidden regex pattern"
    );
    assert!(has_unused_string_issue, "Should detect unused string");
}

#[test]
fn test_lint_with_fixes() {
    let config = Config::default();
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("fixable_rule.yar");

    // Create a rule with fixable issues
    let rule_content = r#"
rule fixable_rule {
    meta:
        desc = "This should be renamed to description"
        author = "Test Author"
    
    strings:
        $unused = "This string is not used"
        $used = "This string is used"
    
    condition:
        $used
}
"#;

    fs::write(&file_path, rule_content).unwrap();

    // Lint with fixes enabled
    let results = lint_files(&[&file_path], &config, true).unwrap();

    // Check that fixes were applied
    assert!(
        results.fixed_count > 0,
        "Should have applied at least one fix"
    );

    // Read the fixed content
    let fixed_content = fs::read_to_string(&file_path).unwrap();

    // Check if fixes were applied correctly
    assert!(
        fixed_content.contains("description ="),
        "Should rename desc to description"
    );
}
