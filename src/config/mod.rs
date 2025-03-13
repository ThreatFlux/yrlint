use anyhow::{Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Default configuration file name
pub const DEFAULT_CONFIG_NAME: &str = ".yrlint.yml";

/// Configuration for the YARA rule linter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Required metadata fields in YARA rules
    #[serde(default = "default_required_meta")]
    pub required_meta: Vec<String>,

    /// Pattern for rule names
    #[serde(default)]
    pub name_pattern: Option<String>,

    /// Maximum number of strings per rule
    #[serde(default = "default_max_strings")]
    pub max_strings_per_rule: usize,

    /// Minimum length for string atoms to be efficient
    #[serde(default = "default_min_atom_length")]
    pub min_atom_length: usize,

    /// List of regex patterns to forbid (for performance reasons)
    #[serde(default)]
    pub forbid_patterns: Vec<String>,

    /// Allowed YARA modules
    #[serde(default = "default_allowed_modules")]
    pub allowed_modules: HashSet<String>,

    /// Maximum length of rule names
    #[serde(default = "default_max_rule_name_length")]
    pub max_rule_name_length: usize,

    /// Check for duplicate strings across different rules
    #[serde(default)]
    pub check_cross_rule_duplicates: bool,

    /// Warn about unused strings (not referenced in condition)
    #[serde(default = "default_true")]
    pub warn_unused_strings: bool,

    /// Check condition order (filesize and cheap checks first)
    #[serde(default = "default_true")]
    pub check_condition_order: bool,

    /// Warn about loops with large iteration ranges
    #[serde(default = "default_true")]
    pub warn_large_loops: bool,

    /// Maximum recommended filesize value for loop bounds
    #[serde(default = "default_loop_max_size")]
    pub loop_max_size: usize,

    /// Check for rule complexity (condition depth/size)
    #[serde(default = "default_true")]
    pub check_rule_complexity: bool,

    /// Maximum depth of nested conditions
    #[serde(default = "default_max_condition_depth")]
    pub max_condition_depth: usize,

    /// Enforce YARA-X compatibility
    #[serde(default)]
    pub enforce_yara_x: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            required_meta: default_required_meta(),
            name_pattern: None,
            max_strings_per_rule: default_max_strings(),
            min_atom_length: default_min_atom_length(),
            forbid_patterns: vec![
                String::from(".*"),
                String::from(".+"),
                String::from(".*?"),
                String::from(".{10,}"),
            ],
            allowed_modules: default_allowed_modules(),
            max_rule_name_length: default_max_rule_name_length(),
            check_cross_rule_duplicates: false,
            warn_unused_strings: true,
            check_condition_order: true,
            warn_large_loops: true,
            loop_max_size: default_loop_max_size(),
            check_rule_complexity: true,
            max_condition_depth: default_max_condition_depth(),
            enforce_yara_x: false,
        }
    }
}

fn default_required_meta() -> Vec<String> {
    vec![
        "description".to_string(),
        "author".to_string(),
        "date".to_string(),
    ]
}

fn default_max_strings() -> usize {
    100
}

fn default_min_atom_length() -> usize {
    4
}

fn default_allowed_modules() -> HashSet<String> {
    vec![
        "pe".to_string(),
        "elf".to_string(),
        "math".to_string(),
        "hash".to_string(),
        "cuckoo".to_string(),
        "magic".to_string(),
        "dotnet".to_string(),
        "time".to_string(),
    ]
    .into_iter()
    .collect()
}

fn default_max_rule_name_length() -> usize {
    128
}

fn default_true() -> bool {
    true
}

fn default_loop_max_size() -> usize {
    1024
}

fn default_max_condition_depth() -> usize {
    5
}

/// Load configuration from a YAML file
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let path = path.as_ref();

    // If the specified path exists, use it
    if path.exists() {
        let config_str = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config = serde_yaml::from_str(&config_str)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        info!("Loaded configuration from {}", path.display());
        return Ok(config);
    }

    // If the specified path doesn't exist, check for the default config in the current directory
    let default_path = PathBuf::from(DEFAULT_CONFIG_NAME);
    if default_path.exists() {
        let config_str = fs::read_to_string(&default_path).with_context(|| {
            format!(
                "Failed to read default config file: {}",
                default_path.display()
            )
        })?;

        let config = serde_yaml::from_str(&config_str).with_context(|| {
            format!(
                "Failed to parse default config file: {}",
                default_path.display()
            )
        })?;

        info!(
            "Loaded default configuration from {}",
            default_path.display()
        );
        return Ok(config);
    }

    // If no config file exists, use the default configuration
    warn!("No configuration file found, using default configuration");
    debug!("Default configuration: {:?}", Config::default());
    Ok(Config::default())
}

/// Write the default configuration to a YAML file
pub fn write_default_config<P: AsRef<Path>>(path: P) -> Result<()> {
    let config = Config::default();
    let yaml =
        serde_yaml::to_string(&config).context("Failed to serialize default configuration")?;

    fs::write(path, yaml).context("Failed to write default configuration file")?;

    Ok(())
}
