# Changelog

All notable changes to YRLint will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-10-06

### Changed
- Release builds now attach binaries for Linux (x86_64 glibc and musl, arm64),
  macOS (arm64, x86_64) and Windows (x86_64), each with a SHA-256 checksum,
  plus one CycloneDX SBOM for the release.
- The Docker image builds on Rust 1.99 (Debian 13 trixie) and runs on a
  distroless Debian 13 base as a non-root user.
- Updated `thiserror` to 2.0 and `env_logger` to 0.11. Log output is
  unchanged.
- The crate metadata now points at the real repository,
  <https://github.com/ThreatFlux/yrlint>, and `Cargo.lock` is committed so
  release builds are reproducible.
- The README documents the supported ways to install YRLint: release binaries,
  `cargo install --git`, building from source and Docker.

### Removed
- Unused `indicatif` and `pretty_assertions` dependencies. This also drops the
  unmaintained `number_prefix` crate (RUSTSEC-2025-0119) from the dependency
  tree.

## [0.1.3] - 2026-08-10

### Changed
- First tagged release with the 0.1.2 changes; v0.1.2 was prepared but never
  tagged.

## [0.1.2] - 2026-08-10

### Fixed
- Scoped the release workflow's token permissions to the minimum the release job needs.

## [0.1.1] - 2026-08-07

### Added
- Initial release of YRLint
- YARA rule parsing using Boreal parser
- Configurable linting through YAML configuration files
- Comprehensive lint rules:
  - Metadata requirements and consistency
  - Rule naming conventions
  - String performance optimizations
  - Condition complexity and ordering
  - YARA-X compatibility
- Multiple output formats: text, JSON, and GitHub Actions
- Automatic fixing of certain issues
- Recursive directory scanning and glob pattern support
- Comprehensive test suite
