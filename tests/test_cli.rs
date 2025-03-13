use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use yrlint::cli::Cli;

#[test]
fn test_cli_find_rule_files() {
    let temp_dir = tempdir().unwrap();

    // Create test YARA files
    let file1_path = temp_dir.path().join("test1.yar");
    let file2_path = temp_dir.path().join("test2.yara");
    let file3_path = temp_dir.path().join("test3.txt"); // Not a YARA file

    fs::write(&file1_path, "rule test1 { condition: true }").unwrap();
    fs::write(&file2_path, "rule test2 { condition: true }").unwrap();
    fs::write(&file3_path, "This is not a YARA rule").unwrap();

    // Create subdirectory with a YARA file
    let subdir_path = temp_dir.path().join("subdir");
    fs::create_dir(&subdir_path).unwrap();
    let file4_path = subdir_path.join("test4.yar");
    fs::write(&file4_path, "rule test4 { condition: true }").unwrap();

    // Test with a specific file
    let cli = Cli {
        paths: vec![file1_path.clone()],
        config: PathBuf::from(".yrlint.yml"),
        format: "text".to_string(),
        fix: false,
        no_fail: false,
        include: "*.yar,*.yara".to_string(),
        exclude: None,
        recursive: false,
    };

    let files = cli.find_rule_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0], file1_path);

    // Test with a directory (non-recursive)
    let cli = Cli {
        paths: vec![temp_dir.path().to_path_buf()],
        config: PathBuf::from(".yrlint.yml"),
        format: "text".to_string(),
        fix: false,
        no_fail: false,
        include: "*.yar,*.yara".to_string(),
        exclude: None,
        recursive: false,
    };

    let files = cli.find_rule_files().unwrap();
    assert_eq!(files.len(), 2); // Should find only test1.yar and test2.yara, not test3.txt or subdirectory files

    // Test with a directory (recursive)
    let cli = Cli {
        paths: vec![temp_dir.path().to_path_buf()],
        config: PathBuf::from(".yrlint.yml"),
        format: "text".to_string(),
        fix: false,
        no_fail: false,
        include: "*.yar,*.yara".to_string(),
        exclude: None,
        recursive: true,
    };

    let files = cli.find_rule_files().unwrap();
    assert_eq!(files.len(), 3); // Should find test1.yar, test2.yara, and subdir/test4.yar

    // Test with exclusion pattern
    let cli = Cli {
        paths: vec![temp_dir.path().to_path_buf()],
        config: PathBuf::from(".yrlint.yml"),
        format: "text".to_string(),
        fix: false,
        no_fail: false,
        include: "*.yar,*.yara".to_string(),
        exclude: Some("*.yara".to_string()),
        recursive: true,
    };

    let files = cli.find_rule_files().unwrap();
    assert_eq!(files.len(), 2); // Should find test1.yar and subdir/test4.yar, but not test2.yara
}
