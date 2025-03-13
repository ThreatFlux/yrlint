# YRLint - YARA Rule Linter

A linter for YARA rules that checks for best practices, performance issues, and correctness.

## Features

- Validates YARA rule syntax and structure
- Checks rule metadata for completeness
- Enforces naming conventions and best practices
- Identifies potential performance issues in strings and conditions
- Ensures compatibility with YARA-X (optional)
- Configurable via YAML
- Multiple output formats (text, JSON, GitHub Actions)
- Automatic fixing of some common issues

## Installation

### From Cargo

```bash
cargo install yrlint
```

### From Source

```bash
git clone https://github.com/username/yrlint.git
cd yrlint
cargo build --release
```

The binary will be available at `target/release/yrlint`.

## Usage

Basic usage:

```bash
yrlint [options] <path> [<path> ...]
```

Example:

```bash
# Lint a single file
yrlint malware.yar

# Lint all YARA files in a directory
yrlint rules/

# Lint with custom configuration
yrlint -c my-config.yml rules/

# Lint and fix issues automatically
yrlint --fix rules/

# Lint recursively
yrlint -r rules/
```

### Options

```
-c, --config <config>    Path to the configuration file [default: .yrlint.yml]
-f, --format <format>    Output format (text, json, github) [default: text]
--fix                    Fix issues automatically where possible
--no-fail                Don't fail on lint errors
-i, --include <include>  File glob patterns to include [default: *.yar,*.yara]
-e, --exclude <exclude>  File glob patterns to exclude
-r, --recursive          Recursively search directories
-h, --help               Print help
-V, --version            Print version
```

## Configuration

YRLint can be configured via a YAML file. By default, it looks for `.yrlint.yml` in the current directory, but you can specify a different file with the `-c` option.

Example configuration:

```yaml
# Required metadata fields
required_meta:
  - description
  - author
  - date

# Pattern for rule names (regex)
name_pattern: '^[A-Z]{3}_[A-Za-z0-9_]+$'

# Maximum number of strings per rule
max_strings_per_rule: 100

# Minimum length for string atoms to be efficient
min_atom_length: 4

# List of regex patterns to forbid (for performance reasons)
forbid_patterns:
  - ".*"
  - ".+"

# Allowed YARA modules
allowed_modules:
  - pe
  - elf
  - math
  - hash
  - cuckoo
  - magic
  - dotnet
  - time

# Check condition order (filesize and cheap checks first)
check_condition_order: true

# Warn about loops with large iteration ranges
warn_large_loops: true

# Maximum recommended filesize value for loop bounds
loop_max_size: 1024

# Enforce YARA-X compatibility
enforce_yara_x: false
```

## Issue Types

YRLint checks for a wide range of issues, including:

### Structural Issues
- Missing required sections
- Unbalanced structures (braces, parentheses)
- YARA-X compatibility issues

### Metadata Issues
- Missing required metadata fields
- Empty metadata values
- Inconsistent metadata field names

### Naming Issues
- Rule names that are too long
- Rule names that don't match the required pattern
- Non-descriptive rule names

### String Issues
- Too many strings in a rule
- Unused strings
- Short strings that may match too frequently
- Inefficient regex patterns
- Hex strings with too many wildcards

### Condition Issues
- Loops with large iteration ranges
- Inefficient condition ordering
- Overly complex conditions
- Use of disallowed modules
- Unused imports

## Exit Codes

- `0`: No issues found or only info/warning issues found
- `1`: Error issues found or linter encountered a problem

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
