use std::fs;
use std::path::Path;
use tempfile::tempdir;
use yrlint::config::{load_config, write_default_config, Config};

#[test]
fn test_default_config() {
    let config = Config::default();

    // Check default values
    assert_eq!(config.min_atom_length, 4);
    assert_eq!(config.max_strings_per_rule, 100);
    assert!(config.required_meta.contains(&"description".to_string()));
    assert!(config.required_meta.contains(&"author".to_string()));
    assert!(config.required_meta.contains(&"date".to_string()));
}

#[test]
fn test_load_config() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("test_config.yml");

    // Create a test config file
    let config_content = r#"
# Test config
required_meta:
  - description
  - author
  - date
  - test_field
min_atom_length: 6
max_strings_per_rule: 50
"#;

    fs::write(&config_path, config_content).unwrap();

    // Load the config
    let config = load_config(&config_path).unwrap();

    // Check loaded values
    assert_eq!(config.min_atom_length, 6);
    assert_eq!(config.max_strings_per_rule, 50);
    assert!(config.required_meta.contains(&"test_field".to_string()));
}

#[test]
fn test_write_default_config() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("default_config.yml");

    // Write default config
    write_default_config(&config_path).unwrap();

    // Check that the file exists
    assert!(config_path.exists());

    // Load the written config
    let config = load_config(&config_path).unwrap();

    // Check that it matches default values
    let default_config = Config::default();
    assert_eq!(config.min_atom_length, default_config.min_atom_length);
    assert_eq!(
        config.max_strings_per_rule,
        default_config.max_strings_per_rule
    );
}

#[test]
fn test_load_nonexistent_config() {
    // Try to load a config that doesn't exist
    let config = load_config(Path::new("nonexistent_config.yml")).unwrap();

    // Should return default config
    let default_config = Config::default();
    assert_eq!(config.min_atom_length, default_config.min_atom_length);
}
