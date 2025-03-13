# Contributing to YRLint

Thank you for considering contributing to YRLint! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/yrlint.git`
3. Create a new branch for your feature: `git checkout -b feature-name`
4. Install development dependencies: `cargo build`

## Development Workflow

### Building the Project

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

To run integration tests (requires the binary to be built):

```bash
RUN_INTEGRATION_TESTS=1 cargo test -- --ignored
```

### Linting

```bash
cargo clippy
```

### Formatting

```bash
cargo fmt
```

## Pull Request Process

1. Ensure your code passes all tests and linting
2. Update documentation if needed
3. Add tests for new features
4. Create a pull request with a clear description of the changes

## Project Structure

- `src/cli/` - Command-line interface
- `src/config/` - Configuration handling
- `src/parser/` - YARA rule parsing
- `src/linter/` - Core linting functionality
  - `src/linter/rules/` - Individual lint rules
- `src/output/` - Output formatting
- `tests/` - Unit and integration tests
- `examples/` - Example YARA rules

## Adding New Lint Rules

1. Decide which category your rule belongs to (metadata, naming, strings, condition, structure)
2. Add your rule to the appropriate file in `src/linter/rules/`
3. Update the config structure in `src/config/mod.rs` if your rule needs configuration
4. Add tests for your rule in `tests/test_linter_rules.rs`

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create a new GitHub release with release notes

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
