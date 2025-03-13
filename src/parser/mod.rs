use anyhow::{Context, Result};
use log::debug;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// YARA parsing errors
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Failed to read file: {0}")]
    FileReadError(#[from] std::io::Error),

    #[error("Failed to parse YARA rule: {0}")]
    ParseError(String),

    #[error("No valid rules found in file")]
    NoRulesFound,
}

/// Represents a parsed YARA rule
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Rule {
    /// Rule name
    pub name: String,

    /// Rule tags
    pub tags: Vec<String>,

    /// Rule modifiers (e.g., private, global)
    pub modifiers: Vec<String>,

    /// Source file path
    pub source_file: PathBuf,

    /// Line number in source file
    pub line_number: usize,

    /// Metadata key-value pairs
    pub metadata: HashMap<String, String>,

    /// Defined strings
    pub strings: Vec<StringDefinition>,

    /// References to strings in the condition
    pub string_refs: Vec<String>,

    /// Raw condition text
    pub condition: String,

    /// Modules used in the rule
    pub modules: Vec<String>,

    /// Raw rule source
    pub source: String,
}

/// Represents a string definition in a YARA rule
#[derive(Debug, Clone)]
pub struct StringDefinition {
    /// String identifier
    pub identifier: String,

    /// String type (text, hex, regex)
    pub string_type: StringType,

    /// String value
    pub value: String,

    /// String modifiers
    pub modifiers: Vec<String>,

    /// Whether the string is marked as private (prefixed with '_')
    pub is_private: bool,
}

/// Types of strings in YARA rules
#[derive(Debug, Clone, PartialEq)]
pub enum StringType {
    Text,
    Hex,
    Regex,
}

/// Parse a YARA rule file
pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Vec<Rule>> {
    let path = path.as_ref();
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read YARA rule file: {}", path.display()))?;

    parse_content(&content, path)
}

/// Parse YARA rule content
pub fn parse_content<P: AsRef<Path>>(content: &str, path: P) -> Result<Vec<Rule>> {
    let path = path.as_ref();
    debug!("Parsing YARA file: {}", path.display());

    // Simple regex-based parser for YARA rules
    let mut rules = Vec::new();

    // Match rule structure
    let rule_regex = r"(?m)^\s*(?:(?:global|private)\s+)*rule\s+([a-zA-Z0-9_]+)(?:\s*:\s*([a-zA-Z0-9_\s]+))?\s*\{([\s\S]*?)\}";
    let rule_pattern = match Regex::new(rule_regex) {
        Ok(re) => re,
        Err(e) => return Err(ParseError::ParseError(format!("Invalid rule regex: {}", e)).into()),
    };

    // Find all rules in the content
    for cap in rule_pattern.captures_iter(content) {
        let name = cap.get(1).map_or("", |m| m.as_str()).to_string();
        let tags_str = cap.get(2).map_or("", |m| m.as_str());
        let tags = tags_str
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        let rule_body = cap.get(3).map_or("", |m| m.as_str());
        let rule_text = cap.get(0).map_or("", |m| m.as_str()).to_string();
        let line_number = content[..cap.get(0).unwrap().start()].lines().count() + 1;

        // Determine if rule has modifiers
        let modifiers_regex = r"(?m)^\s*(global|private)\s+rule";
        let modifiers_pattern = match Regex::new(modifiers_regex) {
            Ok(re) => re,
            Err(e) => {
                return Err(
                    ParseError::ParseError(format!("Invalid modifiers regex: {}", e)).into(),
                )
            }
        };

        let modifiers = modifiers_pattern
            .captures_iter(&rule_text)
            .filter_map(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .collect::<Vec<_>>();

        // Extract metadata
        let metadata = extract_metadata(rule_body)?;

        // Extract strings
        let (strings, string_refs) = extract_strings(rule_body)?;

        // Extract condition
        let condition = extract_condition(rule_body)?;

        // Extract modules (imported)
        let modules = extract_modules(content)?;

        rules.push(Rule {
            name,
            tags,
            modifiers,
            source_file: path.to_path_buf(),
            line_number,
            metadata,
            strings,
            string_refs,
            condition,
            modules,
            source: rule_text,
        });
    }

    if rules.is_empty() {
        return Err(ParseError::NoRulesFound.into());
    }

    debug!(
        "Successfully parsed {} rules from {}",
        rules.len(),
        path.display()
    );
    Ok(rules)
}

/// Extract metadata from rule body
fn extract_metadata(rule_body: &str) -> Result<HashMap<String, String>> {
    let mut metadata = HashMap::new();

    // Match metadata section
    let meta_regex = r"meta:\s*([\s\S]*?)(?:strings:|condition:|$)";
    let meta_pattern = match Regex::new(meta_regex) {
        Ok(re) => re,
        Err(e) => {
            return Err(ParseError::ParseError(format!("Invalid metadata regex: {}", e)).into())
        }
    };

    if let Some(cap) = meta_pattern.captures(rule_body) {
        let meta_content = cap.get(1).map_or("", |m| m.as_str());

        // Match key = value pairs
        let kv_regex = r#"([a-zA-Z0-9_]+)\s*=\s*(?:"([^"]*)"|([0-9]+)|true|false)"#;
        let kv_pattern = match Regex::new(kv_regex) {
            Ok(re) => re,
            Err(e) => {
                return Err(
                    ParseError::ParseError(format!("Invalid key-value regex: {}", e)).into(),
                )
            }
        };

        for kv_cap in kv_pattern.captures_iter(meta_content) {
            let key = kv_cap.get(1).map_or("", |m| m.as_str()).to_string();
            let value = kv_cap
                .get(2)
                .or_else(|| kv_cap.get(3))
                .map_or("", |m| m.as_str())
                .to_string();

            if !key.is_empty() {
                metadata.insert(key, value);
            }
        }
    }

    Ok(metadata)
}

/// Extract strings and string references from rule body
fn extract_strings(rule_body: &str) -> Result<(Vec<StringDefinition>, Vec<String>)> {
    let mut strings = Vec::new();
    let mut string_refs = Vec::new();

    // Match strings section
    let strings_regex = r"strings:\s*([\s\S]*?)(?:condition:|$)";
    let strings_pattern = match Regex::new(strings_regex) {
        Ok(re) => re,
        Err(e) => {
            return Err(ParseError::ParseError(format!("Invalid strings regex: {}", e)).into())
        }
    };

    if let Some(cap) = strings_pattern.captures(rule_body) {
        let strings_content = cap.get(1).map_or("", |m| m.as_str());

        // Match string definitions - handle each type separately for better reliability

        // Text strings: $id = "text"
        let text_regex = r#"(\$[a-zA-Z0-9_]+)\s*=\s*"([^"]*)"\s*([a-z\s]*)"#;
        let text_pattern = match Regex::new(text_regex) {
            Ok(re) => re,
            Err(e) => {
                return Err(
                    ParseError::ParseError(format!("Invalid text string regex: {}", e)).into(),
                )
            }
        };

        for s_cap in text_pattern.captures_iter(strings_content) {
            let identifier = s_cap.get(1).map_or("", |m| m.as_str()).to_string();
            let is_private = identifier.starts_with("$_");
            let value = s_cap.get(2).map_or("", |m| m.as_str()).to_string();
            let modifiers_str = s_cap.get(3).map_or("", |m| m.as_str());

            let modifiers = modifiers_str
                .split_whitespace()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();

            strings.push(StringDefinition {
                identifier: identifier.clone(),
                string_type: StringType::Text,
                value,
                modifiers,
                is_private,
            });

            string_refs.push(identifier);
        }

        // Hex strings: $id = { bytes }
        let hex_regex = r"(\$[a-zA-Z0-9_]+)\s*=\s*\{([^}]*)\}";
        let hex_pattern = match Regex::new(hex_regex) {
            Ok(re) => re,
            Err(e) => {
                return Err(
                    ParseError::ParseError(format!("Invalid hex string regex: {}", e)).into(),
                )
            }
        };

        for s_cap in hex_pattern.captures_iter(strings_content) {
            let identifier = s_cap.get(1).map_or("", |m| m.as_str()).to_string();
            let is_private = identifier.starts_with("$_");
            let value = s_cap.get(2).map_or("", |m| m.as_str()).to_string();

            strings.push(StringDefinition {
                identifier: identifier.clone(),
                string_type: StringType::Hex,
                value,
                modifiers: Vec::new(),
                is_private,
            });

            string_refs.push(identifier);
        }

        // Regex strings: $id = /regex/ modifiers
        let regex_regex = r"(\$[a-zA-Z0-9_]+)\s*=\s*/([^/]*)/\s*([a-z]*)";
        let regex_pattern = match Regex::new(regex_regex) {
            Ok(re) => re,
            Err(e) => {
                return Err(
                    ParseError::ParseError(format!("Invalid regex string regex: {}", e)).into(),
                )
            }
        };

        for s_cap in regex_pattern.captures_iter(strings_content) {
            let identifier = s_cap.get(1).map_or("", |m| m.as_str()).to_string();
            let is_private = identifier.starts_with("$_");
            let value = s_cap.get(2).map_or("", |m| m.as_str()).to_string();
            let modifiers_str = s_cap.get(3).map_or("", |m| m.as_str());

            let modifiers = modifiers_str.chars().map(|c| c.to_string()).collect();

            strings.push(StringDefinition {
                identifier: identifier.clone(),
                string_type: StringType::Regex,
                value,
                modifiers,
                is_private,
            });

            string_refs.push(identifier);
        }
    }

    // Match condition to find actual string references
    let condition_regex = r"condition:\s*([\s\S]*)$";
    let condition_pattern = match Regex::new(condition_regex) {
        Ok(re) => re,
        Err(e) => {
            return Err(ParseError::ParseError(format!("Invalid condition regex: {}", e)).into())
        }
    };

    if let Some(cap) = condition_pattern.captures(rule_body) {
        let condition = cap.get(1).map_or("", |m| m.as_str());

        // Filter string_refs to those actually used in condition
        string_refs.retain(|id| condition.contains(id));
    } else {
        // If no condition found, clear string_refs
        string_refs.clear();
    }

    Ok((strings, string_refs))
}

/// Extract condition from rule body
fn extract_condition(rule_body: &str) -> Result<String> {
    let condition_regex = r"condition:\s*([\s\S]*)$";
    let condition_pattern = match Regex::new(condition_regex) {
        Ok(re) => re,
        Err(e) => {
            return Err(ParseError::ParseError(format!("Invalid condition regex: {}", e)).into())
        }
    };

    let condition = condition_pattern
        .captures(rule_body)
        .and_then(|cap| cap.get(1))
        .map_or(String::new(), |m| m.as_str().trim().to_string());

    Ok(condition)
}

/// Extract imported modules
fn extract_modules(content: &str) -> Result<Vec<String>> {
    let module_regex = r#"import\s+"([a-zA-Z0-9_]+)"#;
    let module_pattern = match Regex::new(module_regex) {
        Ok(re) => re,
        Err(e) => {
            return Err(ParseError::ParseError(format!("Invalid module regex: {}", e)).into())
        }
    };

    let modules = module_pattern
        .captures_iter(content)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect();

    Ok(modules)
}
