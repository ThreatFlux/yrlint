use std::collections::HashMap;
use std::path::PathBuf;
use yrlint::config::Config;
use yrlint::linter::rules::{
    check_condition, check_metadata, check_naming, check_strings, check_structure,
};
use yrlint::parser::{Rule, StringDefinition, StringType};

// Helper function to create a basic test rule
fn create_test_rule(name: &str) -> Rule {
    Rule {
        name: name.to_string(),
        tags: vec!["tag1".to_string(), "tag2".to_string()],
        modifiers: Vec::new(),
        source_file: PathBuf::from("test.yar"),
        line_number: 1,
        metadata: HashMap::new(),
        strings: Vec::new(),
        string_refs: Vec::new(),
        condition: "true".to_string(),
        modules: Vec::new(),
        source: format!("rule {} {{ condition: true }}", name),
    }
}

#[test]
fn test_check_metadata() {
    let mut rule = create_test_rule("test_rule");
    let config = Config::default();

    // Rule without required metadata should have issues
    let issues = check_metadata::check(&rule, &config);
    assert!(!issues.is_empty());

    // Add metadata and check again
    rule.metadata
        .insert("description".to_string(), "Test rule".to_string());
    rule.metadata
        .insert("author".to_string(), "Test Author".to_string());
    rule.metadata
        .insert("date".to_string(), "2023-08-01".to_string());

    let issues = check_metadata::check(&rule, &config);
    assert!(issues.is_empty());

    // Test inconsistent naming
    rule.metadata.clear();
    rule.metadata
        .insert("desc".to_string(), "Test rule".to_string()); // Should be 'description'
    rule.metadata
        .insert("author".to_string(), "Test Author".to_string());
    rule.metadata
        .insert("date".to_string(), "2023-08-01".to_string());

    let issues = check_metadata::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "INCONSISTENT_META_NAME"));

    // Test empty value
    rule.metadata.clear();
    rule.metadata
        .insert("description".to_string(), "".to_string()); // Empty value
    rule.metadata
        .insert("author".to_string(), "Test Author".to_string());
    rule.metadata
        .insert("date".to_string(), "2023-08-01".to_string());

    let issues = check_metadata::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "EMPTY_META_VALUE"));
}

#[test]
fn test_check_naming() {
    let config = Config {
        name_pattern: Some("^[A-Z]{3}_[A-Za-z0-9_]+$".to_string()),
        max_rule_name_length: 50,
        ..Default::default()
    };

    // Test rule with good name pattern
    let rule = create_test_rule("MAL_Ransomware_Test");
    let issues = check_naming::check(&rule, &config);
    assert!(issues.is_empty());

    // Test rule with bad name pattern
    let rule = create_test_rule("bad_name");
    let issues = check_naming::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "RULE_NAME_PATTERN"));

    // Test rule with too long name
    let long_name = "A".repeat(60);
    let rule = create_test_rule(&long_name);
    let issues = check_naming::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "RULE_NAME_TOO_LONG"));

    // Test rule with no vowels (non-descriptive)
    let rule = create_test_rule("MLWR");
    let issues = check_naming::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "RULE_NAME_NO_VOWELS"));
}

#[test]
fn test_check_strings() {
    let mut rule = create_test_rule("test_rule");
    let config = Config {
        min_atom_length: 4,
        forbid_patterns: vec![".*".to_string(), ".+".to_string()],
        ..Default::default()
    };

    // Add a short string
    rule.strings.push(StringDefinition {
        identifier: "$short".to_string(),
        string_type: StringType::Text,
        value: "\"ab\"".to_string(), // 2 bytes, less than min_atom_length
        modifiers: Vec::new(),
        is_private: false,
    });

    // Add a forbidden regex pattern
    rule.strings.push(StringDefinition {
        identifier: "$bad_regex".to_string(),
        string_type: StringType::Regex,
        value: "/.*example/".to_string(), // Contains forbidden pattern
        modifiers: Vec::new(),
        is_private: false,
    });

    // Add a good string
    rule.strings.push(StringDefinition {
        identifier: "$good".to_string(),
        string_type: StringType::Text,
        value: "\"good string\"".to_string(),
        modifiers: Vec::new(),
        is_private: false,
    });

    // Add a string with nocase on a short string
    rule.strings.push(StringDefinition {
        identifier: "$nocase_short".to_string(),
        string_type: StringType::Text,
        value: "\"abc\"".to_string(),
        modifiers: vec!["nocase".to_string()],
        is_private: false,
    });

    // Only reference the good string in the condition
    rule.string_refs = vec!["$good".to_string()];
    rule.condition = "any of ($good)".to_string();

    let issues = check_strings::check(&rule, &config);

    // Should have issues for short string, bad regex, and unused strings
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "SHORT_STRING"));
    assert!(issues.iter().any(|i| i.code == "FORBIDDEN_REGEX_PATTERN"));
    assert!(issues.iter().any(|i| i.code == "UNUSED_STRING"));
    assert!(issues.iter().any(|i| i.code == "NOCASE_ON_SHORT_STRING"));
}

#[test]
fn test_check_condition() {
    let mut rule = create_test_rule("test_rule");
    let config = Config::default();

    // Test loop with filesize
    rule.condition = "for any i in (1..filesize) : ( uint8(i) == 0x90 )".to_string();

    let issues = check_condition::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "LARGE_LOOP_RANGE"));

    // Test inefficient condition ordering
    rule.condition = "$string and filesize < 100".to_string();
    rule.string_refs = vec!["$string".to_string()];
    rule.strings = vec![StringDefinition {
        identifier: "$string".to_string(),
        string_type: StringType::Text,
        value: "\"test\"".to_string(),
        modifiers: Vec::new(),
        is_private: false,
    }];

    let issues = check_condition::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues
        .iter()
        .any(|i| i.code == "INEFFICIENT_CONDITION_ORDER"));

    // Test complex condition
    rule.condition = "(((((($string))))) and (((filesize < 100))))".to_string();

    let issues = check_condition::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "CONDITION_TOO_COMPLEX"));
}

#[test]
fn test_check_structure() {
    let mut rule = create_test_rule("test_rule");
    let config = Config {
        enforce_yara_x: true,
        ..Default::default()
    };

    // Test YARA-X duplicate modifier
    rule.source = "private private rule test_rule { condition: true }".to_string();

    let issues = check_structure::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "YARA_X_DUPLICATE_MODIFIER"));

    // Test undefined string reference
    rule.source = "rule test_rule { condition: $undefined }".to_string();
    rule.string_refs = vec!["$undefined".to_string()];
    rule.strings = Vec::new();

    let issues = check_structure::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "UNDEFINED_STRING"));

    // Test missing condition
    rule.source = "rule test_rule { strings: $a = \"test\" }".to_string();
    rule.condition = "".to_string();

    let issues = check_structure::check(&rule, &config);
    assert!(!issues.is_empty());
    assert!(issues.iter().any(|i| i.code == "MISSING_CONDITION"));
}
