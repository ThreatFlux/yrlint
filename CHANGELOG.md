# Changelog

All notable changes to YRLint will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
