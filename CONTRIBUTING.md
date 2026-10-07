# Contributing to YRLint

Thank you for considering contributing to YRLint! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project.

## Getting Started

1. Fork the repository
2. Clone your fork, replacing `YOUR_USERNAME` with your GitHub username: `git clone https://github.com/YOUR_USERNAME/yrlint.git`
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

Releases are automated. Pull requests are squash-merged, and the pull request
title becomes the commit subject on `main`, so give it a
[Conventional Commits](https://www.conventionalcommits.org/) prefix:

- `feat:` releases a new minor version, `fix:` a new patch version, and a
  breaking change (`feat!:` or a `BREAKING CHANGE:` footer) a new major version.
- `ci:`, `build:`, `chore:`, `docs:`, `test:` and `refactor:` do not cut a
  release.

When CI and Security pass for a push to `main`, the Auto Release workflow bumps
the version in `Cargo.toml` and `Cargo.lock`, tags `vX.Y.Z` and creates the
GitHub release as the ThreatFlux automation app. The tag starts the Release
workflow, which builds the binaries, checksums and SBOM, attaches them to the
release and publishes the crate to crates.io through trusted publishing.

Publishing to crates.io is switched off until the crate's first publish: the
repository variable `CRATES_IO_PUBLISH` is `false`, so releases skip that step,
because crates.io trusted publishing cannot create a new crate.

### First crates.io publish (one time)

A maintainer publishes the first version by hand from a release tag, with a
short-lived API token:

1. On crates.io, create an API token under Account Settings > API Tokens with
   the `publish-new` scope, restricted to the `yrlint` crate name, with the
   shortest expiry available.
2. Publish from a clean checkout of the release tag:

   ```bash
   git clone --depth 1 --branch vX.Y.Z https://github.com/ThreatFlux/yrlint /tmp/yrlint-publish
   cd /tmp/yrlint-publish
   cargo login            # paste the token when prompted
   cargo publish --locked -p yrlint
   cargo logout
   ```

3. Revoke the token on crates.io.

Then switch the repository to trusted publishing:

1. On the crate's crates.io Settings > Trusted Publishing page, add a GitHub
   publisher: owner `ThreatFlux`, repository `yrlint`, workflow `release.yml`,
   environment `crates-io`.
2. Delete the `CRATES_IO_PUBLISH` repository variable
   (`gh variable delete CRATES_IO_PUBLISH -R ThreatFlux/yrlint`), so the next
   release publishes through the Release workflow.
3. On the same crates.io settings page, turn on "Require trusted publishing" so
   API tokens can no longer publish the crate.

Both workflows can be rehearsed without tagging, releasing or publishing
anything. The release dry run still builds every binary and the SBOM and keeps
them as artifacts of that workflow run:

```bash
gh workflow run auto-release.yml -f dry_run=true
gh workflow run release.yml -f version=X.Y.Z -f dry_run=true
```

Add user-facing changes to the `[Unreleased]` section of `CHANGELOG.md` as you
go, and move them under a `## [X.Y.Z] - YYYY-MM-DD` heading before the release
is cut. Auto Release writes release notes only from `feat:`, `fix:` and breaking
change subjects; the Release workflow replaces them with the `## [X.Y.Z]`
section of `CHANGELOG.md` when one exists.

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
