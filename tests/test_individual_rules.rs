use std::collections::HashMap;
use std::path::PathBuf;
use yrlint::config::Config;
use yrlint::linter::rules::{
    check_condition, check_metadata, check_naming, check_strings, check_structure,
};
use yrlint::parser::{Rule, StringDefinition, StringType};

// Helper function to create a basic test rule
fn create_test_rule() -> Rule {
    Rule {
        name: "test_rule".to_string(),
        tags: vec!["tag1".to_string(), "tag2".to_string()],
        modifiers: vec![],
        source_file: PathBuf::from("test.yar"),
        line_number: 1,
        metadata: {
            let mut map = HashMap::new();
            map.insert("description".to_string(), "Test description".to_string());
            map.insert("author".to_string(), "Test Author".to_string());
            map.insert("date".to_string(), "2023-01-01".to_string());
            map
        },
        strings: vec![
            StringDefinition {
                identifier: "$test_string".to_string(),
                string_type: StringType::Text,
                value: "\"test string value\"".to_string(),
                modifiers: vec![],
                is_private: false,
            },
            StringDefinition {
                identifier: "$test_regex".to_string(),
                string_type: StringType::Regex,
                value: "/test[0-9]+/".to_string(),
                modifiers: vec![],
                is_private: false,
            },
        ],
        string_refs: vec!["$test_string".to_string(), "$test_regex".to_string()],
        condition: "any of them".to_string(),
        modules: vec![],
        source: "rule test_rule { condition: any of them }".to_string(),
    }
}

#[test]
fn test_check_metadata() {
    let config = Config::default();

    // Test with all required metadata present
    let rule = create_test_rule();
    let issues = check_metadata::check(&rule, &config);
    assert!(
        issues.is_empty(),
        "No issues should be found with complete metadata"
    );

    // Test with missing metadata
    let mut rule = create_test_rule();
    rule.metadata.remove("description");
    let issues = check_metadata::check(&rule, &config);
    assert!(
        !issues.is_empty(),
        "Issues should be found with missing metadata"
    );
    assert_eq!(issues[0].code, "MISSING_REQUIRED_META");

    // Test with inconsistent metadata name
    let mut rule = create_test_rule();
    rule.metadata.remove("description");
    rule.metadata
        .insert("desc".to_string(), "Test description".to_string());
    let issues = check_metadata::check(&rule, &config);
    assert!(
        issues.iter().any(|i| i.code == "INCONSISTENT_META_NAME"),
        "Should detect inconsistent metadata name"
    );
}

#[test]
fn test_check_naming() {
    // Test with default config (no name pattern)
    let config = Config::default();
    let rule = create_test_rule();
    let issues = check_naming::check(&rule, &config);

    // Should have info about underscore naming convention
    assert!(
        issues.iter().any(|i| i.code == "RULE_NAME_NO_SEPARATOR"),
        "Should suggest using underscores in name"
    );

    // Test with name pattern
    let mut config = Config::default();
    config.name_pattern = Some("^[A-Z]{3}_.*$".to_string());
    let issues = check_naming::check(&rule, &config);
    assert!(
        issues.iter().any(|i| i.code == "RULE_NAME_PATTERN"),
        "Should detect name not matching pattern"
    );

    // Test with valid name
    let mut rule = create_test_rule();
    rule.name = "MAL_Ransomware_Test".to_string();
    let issues = check_naming::check(&rule, &config);
    assert!(
        !issues.iter().any(|i| i.code == "RULE_NAME_NO_SEPARATOR"),
        "Should not complain about separators with proper name"
    );
}

#[test]
fn test_check_strings() {
    let config = Config::default();

    // Test with normal strings
    let rule = create_test_rule();
    let issues = check_strings::check(&rule, &config);
    assert!(
        issues.is_empty(),
        "No issues should be found with normal strings"
    );

    // Test with short string
    let mut rule = create_test_rule();
    rule.strings[0].value = "\"ab\"".to_string(); // 2 bytes
    let issues = check_strings::check(&rule, &config);
    assert!(
        issues.iter().any(|i| i.code == "SHORT_STRING"),
        "Should detect short string"
    );

    // Test with forbidden regex pattern
    let mut rule = create_test_rule();
    rule.strings[1].value = "/.*test/".to_string(); // Contains .* wildcard
    let issues = check_strings::check(&rule, &config);
    assert!(
        issues.iter().any(|i| i.code == "FORBIDDEN_REGEX_PATTERN"),
        "Should detect forbidden regex pattern"
    );

    // Test with unused string
    let mut rule = create_test_rule();
    rule.string_refs = vec!["$test_string".to_string()]; // Only reference test_string
    let issues = check_strings::check(&rule, &config);
    assert!(
        issues.iter().any(|i| i.code == "UNUSED_STRING"),
        "Should detect unused string"
    );
}

#[test]
fn test_check_condition() {
    let config = Config::default();

    // Test with normal condition
    let rule = create_test_rule();
    let issues = check_condition::check(&rule, &config);
    assert!(
        issues.is_empty(),
        "No issues should be found with simple condition"
    );

    // Test with filesize after string check
    let mut rule = create_test_rule();
    rule.condition = "$test_string and filesize < 1MB".to_string();
    let issues = check_condition::check(&rule, &config);
    assert!(
        issues
            .iter()
            .any(|i| i.code == "INEFFICIENT_CONDITION_ORDER"),
        "Should detect inefficient condition order"
    );

    // Test with large loop
    let mut rule = create_test_rule();
    rule.condition = "for any i in (1..filesize) : ( @test_string[i] == 0 )".to_string();
    let issues = check_condition::check(&rule, &config);
    assert!(
        issues.iter().any(|i| i.code == "LARGE_LOOP_RANGE"),
        "Should detect large loop range"
    );
}

#[test]
fn test_check_structure() {
    // Test with normal rule
    let config = Config::default();
    let rule = create_test_rule();
    let issues = check_structure::check(&rule, &config);
    assert!(
        issues.is_empty(),
        "No issues should be found with valid structure"
    );

    // Test with YARA-X enabled and duplicate modifiers
    let mut config = Config::default();
    config.enforce_yara_x = true;
    let mut rule = create_test_rule();
    rule.source = "private private rule test_rule { condition: true }".to_string();
    let issues = check_structure::check(&rule, &config);
    assert!(
        issues.iter().any(|i| i.code == "YARA_X_DUPLICATE_MODIFIER"),
        "Should detect duplicate modifier with YARA-X enabled"
    );

    // Test with missing condition
    let mut rule = create_test_rule();
    rule.condition = "".to_string();
    let issues = check_structure::check(&rule, &config);
    assert!(
        issues.iter().any(|i| i.code == "MISSING_CONDITION"),
        "Should detect missing condition"
    );

    // Test with unbalanced braces
    let mut rule = create_test_rule();
    rule.source = "rule test_rule { condition: true".to_string(); // Missing closing brace
    let issues = check_structure::check(&rule, &config);
    assert!(
        issues.iter().any(|i| i.code == "UNBALANCED_BRACES"),
        "Should detect unbalanced braces"
    );
}
