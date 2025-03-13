use anyhow::{Context, Result};
use clap::Parser;
use globset::{Glob, GlobSet, GlobSetBuilder};
use log::debug;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// YARA Rule Linter
///
/// Lint YARA rules for best practices and performance issues
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// YARA rule files or directories to lint
    #[arg(required_unless_present = "generate_config")]
    pub paths: Vec<PathBuf>,

    /// Generate a default configuration file
    #[arg(long)]
    pub generate_config: bool,

    /// Path to the configuration file
    #[arg(short, long, default_value = ".yrlint.yml")]
    pub config: PathBuf,

    /// Output format (text, json, github)
    #[arg(short, long, default_value = "text")]
    pub format: String,

    /// Fix issues automatically where possible
    #[arg(short = 'x', long)]
    pub fix: bool,

    /// Don't fail on lint errors
    #[arg(long)]
    pub no_fail: bool,

    /// File glob patterns to include (e.g. "*.yar")
    #[arg(short = 'i', long, default_value = "*.yar,*.yara")]
    pub include: String,

    /// File glob patterns to exclude
    #[arg(short = 'e', long)]
    pub exclude: Option<String>,

    /// Recursively search directories
    #[arg(short, long)]
    pub recursive: bool,
}

impl Cli {
    /// Find all YARA rule files from the provided paths
    pub fn find_rule_files(&self) -> Result<Vec<PathBuf>> {
        let include_patterns = self.parse_glob_patterns(&self.include)?;
        let exclude_patterns = match &self.exclude {
            Some(patterns) => self.parse_glob_patterns(patterns)?,
            None => GlobSet::empty(),
        };

        let mut rule_files = Vec::new();

        for path in &self.paths {
            if path.is_file() {
                if self.is_yara_file(path, &include_patterns, &exclude_patterns) {
                    rule_files.push(path.clone());
                }
            } else if path.is_dir() {
                let walker = if self.recursive {
                    WalkDir::new(path)
                } else {
                    WalkDir::new(path).max_depth(1)
                };

                for entry in walker.into_iter().filter_map(|e| e.ok()) {
                    let entry_path = entry.path();
                    if entry_path.is_file()
                        && self.is_yara_file(entry_path, &include_patterns, &exclude_patterns)
                    {
                        rule_files.push(entry_path.to_path_buf());
                    }
                }
            }
        }

        debug!("Found {} YARA rule files", rule_files.len());
        Ok(rule_files)
    }

    /// Parse a comma-separated list of glob patterns into a GlobSet
    fn parse_glob_patterns(&self, patterns: &str) -> Result<GlobSet> {
        let mut builder = GlobSetBuilder::new();

        for pattern in patterns.split(',') {
            let glob = Glob::new(pattern.trim())
                .with_context(|| format!("Invalid glob pattern: {}", pattern))?;
            builder.add(glob);
        }

        builder.build().context("Failed to build glob set")
    }

    /// Check if a file matches YARA file patterns
    fn is_yara_file(&self, path: &Path, include: &GlobSet, exclude: &GlobSet) -> bool {
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => return false,
        };

        include.is_match(file_name) && !exclude.is_match(file_name)
    }
}
