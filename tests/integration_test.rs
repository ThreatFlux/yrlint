use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

// This test will run the actual binary to test end-to-end functionality
#[test]
#[ignore] // Ignore by default as it requires the binary to be built
fn test_cli_integration() {
    // Skip if not running integration tests
    if std::env::var("RUN_INTEGRATION_TESTS").is_err() {
        return;
    }

    // Build the binary first
    let status = Command::new("cargo")
        .args(["build"])
        .status()
        .expect("Failed to build yrlint");

    assert!(status.success(), "Failed to build yrlint");

    // Create a temp directory for test files
    let temp_dir = tempdir().unwrap();

    // Create a test YARA rule with issues
    let rule_path = temp_dir.path().join("test_rule.yar");
    fs::write(
        &rule_path,
        r#"
rule test_rule {
    strings:
        $a = "a" // Too short
    condition:
        $a
}
"#,
    )
    .unwrap();

    // Run yrlint on the test file
    let output = Command::new("./target/debug/yrlint")
        .arg(rule_path.to_str().unwrap())
        .output()
        .expect("Failed to run yrlint");

    // Check that it produced output and found issues
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SHORT_STRING"),
        "Should detect short string issue"
    );

    // Check that it returns non-zero exit code for errors
    assert!(
        !output.status.success(),
        "Should return non-zero exit code for errors"
    );

    // Test with --no-fail flag
    let output = Command::new("./target/debug/yrlint")
        .arg("--no-fail")
        .arg(rule_path.to_str().unwrap())
        .output()
        .expect("Failed to run yrlint with --no-fail");

    // Should still detect issues but return zero exit code
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SHORT_STRING"),
        "Should still detect short string issue"
    );
    assert!(
        output.status.success(),
        "Should return zero exit code with --no-fail"
    );

    // Test JSON output format
    let output = Command::new("./target/debug/yrlint")
        .args(["--format", "json"])
        .arg(rule_path.to_str().unwrap())
        .output()
        .expect("Failed to run yrlint with JSON output");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("{"), "JSON output should start with {");
    assert!(
        stdout.contains("\"code\":\"SHORT_STRING\""),
        "JSON should contain issue code"
    );
}
