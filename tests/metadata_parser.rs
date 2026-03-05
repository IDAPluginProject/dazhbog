//! Integration tests for the Lumina metadata parser.
//!
//! These tests verify the parser against real-world metadata files
//! from the analysis/data directory.

use dazhbog::protocol::lumina::metadata::parse_metadata;
use std::fs;
use std::path::Path;

/// Get the analysis data directory path.
fn get_data_dir() -> Option<std::path::PathBuf> {
    let dir = std::path::PathBuf::from("analysis/data");
    if dir.exists() {
        Some(dir)
    } else {
        None
    }
}

/// Count files in the data directory.
fn count_bin_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "bin")
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn test_parser_no_panics_on_all_data() {
    let Some(data_dir) = get_data_dir() else {
        eprintln!("Skipping test: analysis/data directory not found");
        return;
    };

    let bin_count = count_bin_files(&data_dir);
    if bin_count == 0 {
        eprintln!("Skipping test: no .bin files found");
        return;
    }

    let test_limit = bin_count.min(1000);
    println!("Testing parser doesn't panic on {} files...", test_limit);

    let mut files_processed = 0usize;

    for entry in fs::read_dir(&data_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.extension().map(|e| e != "bin").unwrap_or(true) {
            continue;
        }

        if files_processed >= test_limit {
            break;
        }

        let data = fs::read(&path).unwrap();

        // This should not panic on any input
        let result = std::panic::catch_unwind(|| parse_metadata(&data));

        assert!(
            result.is_ok(),
            "Parser panicked on file: {}",
            path.display()
        );

        files_processed += 1;
    }

    println!(
        "Successfully parsed {} files without panics",
        files_processed
    );
}

#[test]
fn test_parse_speed() {
    let Some(data_dir) = get_data_dir() else {
        eprintln!("Skipping test: analysis/data directory not found");
        return;
    };

    let bin_count = count_bin_files(&data_dir);
    if bin_count < 100 {
        eprintln!("Skipping speed test: need at least 100 files");
        return;
    }

    let test_limit = bin_count.min(10000);

    // Collect file data first
    let mut file_data: Vec<Vec<u8>> = Vec::new();
    for entry in fs::read_dir(&data_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.extension().map(|e| e != "bin").unwrap_or(true) {
            continue;
        }

        if file_data.len() >= test_limit {
            break;
        }

        file_data.push(fs::read(&path).unwrap());
    }

    println!("Speed test on {} files...", file_data.len());

    let start = std::time::Instant::now();

    for data in &file_data {
        let _ = parse_metadata(data);
    }

    let elapsed = start.elapsed();
    let files_per_sec = file_data.len() as f64 / elapsed.as_secs_f64();

    println!("Parsed {} files in {:?}", file_data.len(), elapsed);
    println!("Speed: {:.0} files/second", files_per_sec);

    assert!(
        files_per_sec > 1000.0,
        "Parser should process at least 1000 files/second"
    );
}
