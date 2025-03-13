mod cli;
mod config;
mod linter;
mod output;
mod parser;

use anyhow::{Context, Result};
use clap::Parser;
use cli::Cli;
use log::{debug, info};

fn main() -> Result<()> {
    // Initialize logger
    env_logger::init();

    // Parse command line arguments
    let cli = Cli::parse();
    debug!("CLI arguments: {:?}", cli);

    // Handle generate-config option
    if cli.generate_config {
        info!(
            "Generating default configuration file to {}",
            cli.config.display()
        );
        config::write_default_config(&cli.config)
            .context("Failed to write default configuration")?;
        return Ok(());
    }

    // Load configuration
    let config = config::load_config(&cli.config).context("Failed to load configuration")?;
    debug!("Loaded configuration: {:?}", config);

    // Find YARA rule files
    let rule_files = cli
        .find_rule_files()
        .context("Failed to find YARA rule files")?;
    info!("Found {} YARA rule files to lint", rule_files.len());

    // Lint each file
    let results =
        linter::lint_files(&rule_files, &config, cli.fix).context("Failed to lint YARA rules")?;

    // Output results
    output::print_results(&results, &cli.format).context("Failed to print results")?;

    // Return non-zero exit code if any errors were found
    if results.has_errors() && !cli.no_fail {
        std::process::exit(1);
    }

    Ok(())
}
