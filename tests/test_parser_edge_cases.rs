use std::path::Path;
use yrlint::parser::{parse_content, Rule, StringType};

#[test]
fn test_parse_empty_rule() {
    let content = r#"
rule empty_rule {
    condition:
        true
}
"#;

    let rules = parse_content(content, Path::new("test_file.yar")).unwrap();
    assert_eq!(rules.len(), 1);
    let rule = &rules[0];
    assert_eq!(rule.name, "empty_rule");
    assert!(rule.metadata.is_empty());
    assert!(rule.strings.is_empty());
    assert!(rule.condition.contains("true"));
}

#[test]
fn test_parse_rule_with_tags() {
    let content = r#"
rule tagged_rule : tag1 tag2 tag3 {
    condition:
        true
}
"#;

    let rules = parse_content(content, Path::new("test_file.yar")).unwrap();
    assert_eq!(rules.len(), 1);
    let rule = &rules[0];
    assert_eq!(rule.tags.len(), 3);
    assert!(rule.tags.contains(&"tag1".to_string()));
    assert!(rule.tags.contains(&"tag2".to_string()));
    assert!(rule.tags.contains(&"tag3".to_string()));
}

#[test]
fn test_parse_multiple_rules() {
    let content = r#"
rule rule1 {
    condition:
        true
}

rule rule2 {
    strings:
        $a = "test"
    condition:
        $a
}

rule rule3 {
    meta:
        author = "Test"
    condition:
        false
}
"#;

    let rules = parse_content(content, Path::new("test_file.yar")).unwrap();
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0].name, "rule1");
    assert_eq!(rules[1].name, "rule2");
    assert_eq!(rules[2].name, "rule3");
}

#[test]
fn test_parse_rule_with_all_string_types() {
    let content = r#"
rule string_types {
    strings:
        $text = "plain text"
        $wide = "wide text" wide
        $nocase = "nocase text" nocase
        $hex = { 90 90 90 }
        $regex = /test[0-9]+/
    condition:
        any of them
}
"#;

    let rules = parse_content(content, Path::new("test_file.yar")).unwrap();
    assert_eq!(rules.len(), 1);
    let rule = &rules[0];

    // Check that we have all 5 strings
    assert_eq!(rule.strings.len(), 5);

    // Find each string by identifier and check its type
    let text = rule
        .strings
        .iter()
        .find(|s| s.identifier == "$text")
        .unwrap();
    let wide = rule
        .strings
        .iter()
        .find(|s| s.identifier == "$wide")
        .unwrap();
    let nocase = rule
        .strings
        .iter()
        .find(|s| s.identifier == "$nocase")
        .unwrap();
    let hex = rule
        .strings
        .iter()
        .find(|s| s.identifier == "$hex")
        .unwrap();
    let regex = rule
        .strings
        .iter()
        .find(|s| s.identifier == "$regex")
        .unwrap();

    assert_eq!(text.string_type, StringType::Text);
    assert_eq!(wide.string_type, StringType::Text);
    assert!(wide.modifiers.contains(&"wide".to_string()));
    assert_eq!(nocase.string_type, StringType::Text);
    assert!(nocase.modifiers.contains(&"nocase".to_string()));
    assert_eq!(hex.string_type, StringType::Hex);
    assert_eq!(regex.string_type, StringType::Regex);
}

#[test]
fn test_parse_rule_with_complex_condition() {
    let content = r#"
rule complex_condition {
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
    condition:
        $a and (
            for any i in (1..#b): (
                @a[i] < @b[i] and @b[i] < @c
            )
        ) or (
            filesize < 100 and
            not $c
        )
}
"#;

    let rules = parse_content(content, Path::new("test_file.yar")).unwrap();
    assert_eq!(rules.len(), 1);
    let rule = &rules[0];

    // Check that the condition contains the expected elements
    assert!(rule.condition.contains("@a"));
    assert!(rule.condition.contains("for any"));
    assert!(rule.condition.contains("filesize"));
}

#[test]
fn test_parse_error_on_malformed_rule() {
    let content = r#"
rule malformed {
    this is not valid YARA syntax
}
"#;

    let result = parse_content(content, Path::new("test_file.yar"));
    assert!(result.is_err());
}

#[test]
fn test_parse_rule_with_imports() {
    let content = r#"
import "pe"
import "hash"

rule with_imports {
    condition:
        pe.is_pe() and hash.md5(0, filesize) == "abcdef0123456789"
}
"#;

    let rules = parse_content(content, Path::new("test_file.yar")).unwrap();
    assert_eq!(rules.len(), 1);

    // The condition should reference the pe and hash modules
    assert!(rules[0].condition.contains("pe.is_pe"));
    assert!(rules[0].condition.contains("hash.md5"));
}

#[test]
fn test_parse_rule_with_private_strings() {
    let content = r#"
rule with_private_strings {
    strings:
        $s1 = "public"
        $_s2 = "private"  // Private string starting with _
    condition:
        any of them
}
"#;

    let rules = parse_content(content, Path::new("test_file.yar")).unwrap();
    assert_eq!(rules.len(), 1);

    let s1 = rules[0]
        .strings
        .iter()
        .find(|s| s.identifier == "$s1")
        .unwrap();
    let s2 = rules[0]
        .strings
        .iter()
        .find(|s| s.identifier == "$_s2")
        .unwrap();

    assert!(!s1.is_private);
    assert!(s2.is_private);
}
