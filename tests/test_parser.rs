use std::path::Path;
use yrlint::parser::{parse_content, StringType};

#[test]
fn test_parse_simple_rule() {
    let content = r#"
rule simple_test {
    meta:
        description = "A simple test rule"
        author = "Test Author"
        date = "2023-08-01"
    
    strings:
        $text = "example text"
        $hex = { 90 90 90 }
        $regex = /test[0-9]+/
    
    condition:
        any of them
}
"#;

    let rules = parse_content(content, Path::new("test_file.yar")).unwrap();

    assert_eq!(rules.len(), 1);
    let rule = &rules[0];

    // Check rule name
    assert_eq!(rule.name, "simple_test");

    // Check metadata
    assert_eq!(
        rule.metadata.get("description").unwrap(),
        "A simple test rule"
    );
    assert_eq!(rule.metadata.get("author").unwrap(), "Test Author");
    assert_eq!(rule.metadata.get("date").unwrap(), "2023-08-01");

    // Check strings
    assert_eq!(rule.strings.len(), 3);

    // Find each string type
    let text_string = rule
        .strings
        .iter()
        .find(|s| s.identifier == "$text")
        .unwrap();
    let hex_string = rule
        .strings
        .iter()
        .find(|s| s.identifier == "$hex")
        .unwrap();
    let regex_string = rule
        .strings
        .iter()
        .find(|s| s.identifier == "$regex")
        .unwrap();

    assert_eq!(text_string.string_type, StringType::Text);
    assert_eq!(hex_string.string_type, StringType::Hex);
    assert_eq!(regex_string.string_type, StringType::Regex);

    // Check condition
    assert!(rule.condition.contains("any of them"));
}

#[test]
fn test_parse_rule_with_modifiers() {
    let content = r#"
private global rule rule_with_modifiers {
    condition:
        true
}
"#;

    let rules = parse_content(content, Path::new("test_file.yar")).unwrap();

    assert_eq!(rules.len(), 1);
    let rule = &rules[0];

    // Check rule name
    assert_eq!(rule.name, "rule_with_modifiers");

    // Check modifiers
    assert!(rule.modifiers.contains(&"private".to_string()));
    assert!(rule.modifiers.contains(&"global".to_string()));
}

#[test]
fn test_parse_error_on_invalid_rule() {
    let content = r#"
rule invalid_rule {
    invalid_section:
        something = "wrong"
    
    strings:
        $a = "test"
    
    // Missing closing brace and condition
"#;

    let result = parse_content(content, Path::new("test_file.yar"));
    assert!(result.is_err());
}
