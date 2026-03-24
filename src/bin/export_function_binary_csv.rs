use dazhbog::config::Config;
use dazhbog::engine::{BinaryMeta, EngineRuntime};

use std::cmp::Ordering;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

struct Args {
    config_path: PathBuf,
    output_path: PathBuf,
}

struct ExportProgress {
    total_binaries: u64,
    total_rows_estimate: u64,
    done_binaries: u64,
    done_rows: u64,
    start: Instant,
    last_draw: Instant,
}

fn print_usage(program: &str) {
    println!("Usage: {program} [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --config <path>      Config file path (default: config.toml)");
    println!("  --output <path>      Output CSV path (default: function_binaries.csv)");
    println!("  --help, -h           Show this help message");
}

fn take_value(args: &[String], i: &mut usize, flag: &str) -> io::Result<String> {
    *i += 1;
    args.get(*i).cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {flag}"),
        )
    })
}

fn parse_args() -> io::Result<Args> {
    let args: Vec<String> = std::env::args().collect();
    let program = args
        .first()
        .map(String::as_str)
        .unwrap_or("export_function_binary_csv");

    let mut parsed = Args {
        config_path: PathBuf::from("config.toml"),
        output_path: PathBuf::from("function_binaries.csv"),
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                parsed.config_path = PathBuf::from(take_value(&args, &mut i, "--config")?);
            }
            "--output" => {
                parsed.output_path = PathBuf::from(take_value(&args, &mut i, "--output")?);
            }
            "--help" | "-h" => {
                print_usage(program);
                std::process::exit(0);
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {other}"),
                ));
            }
        }
        i += 1;
    }

    Ok(parsed)
}

impl ExportProgress {
    fn new(total_binaries: u64, total_rows_estimate: u64) -> Self {
        let now = Instant::now();
        Self {
            total_binaries,
            total_rows_estimate,
            done_binaries: 0,
            done_rows: 0,
            start: now,
            last_draw: now,
        }
    }

    fn advance(&mut self, rows: u64, current_binary: &str, force: bool) {
        self.done_binaries = self.done_binaries.saturating_add(1);
        self.done_rows = self.done_rows.saturating_add(rows);

        let now = Instant::now();
        if force || now.duration_since(self.last_draw).as_millis() >= 100 {
            self.draw(current_binary, false);
            self.last_draw = now;
        }
    }

    fn finish(&self) {
        self.draw("done", true);
    }

    fn draw(&self, current_binary: &str, final_line: bool) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let rows_per_sec = if elapsed > 0.0 {
            self.done_rows as f64 / elapsed
        } else {
            0.0
        };
        let binary_pct = if self.total_binaries > 0 {
            (self.done_binaries as f64 / self.total_binaries as f64).clamp(0.0, 1.0)
        } else {
            1.0
        };
        let row_pct = if self.total_rows_estimate > 0 {
            (self.done_rows as f64 / self.total_rows_estimate as f64).clamp(0.0, 1.0)
        } else {
            binary_pct
        };
        let eta_secs = if self.total_rows_estimate > self.done_rows && rows_per_sec > 0.0 {
            (self.total_rows_estimate - self.done_rows) as f64 / rows_per_sec
        } else {
            0.0
        };

        print!(
            "\rExport {} bin {}/{} ({:>5.1}%) | rows {}/{} ({:>5.1}%) | {:>9}/s | ETA {} | {}\x1b[K",
            progress_bar(binary_pct, 24),
            fmt_num(self.done_binaries),
            fmt_num(self.total_binaries),
            binary_pct * 100.0,
            fmt_num(self.done_rows),
            fmt_num(self.total_rows_estimate),
            row_pct * 100.0,
            fmt_num(rows_per_sec as u64),
            fmt_duration(eta_secs),
            truncate_middle(current_binary, 48),
        );

        if final_line {
            println!();
        }

        let _ = io::stdout().flush();
    }
}

fn cmp_binary_meta(a: &BinaryMeta, b: &BinaryMeta) -> Ordering {
    a.basename
        .cmp(&b.basename)
        .then_with(|| a.last_seen_ts.cmp(&b.last_seen_ts))
        .then_with(|| a.md5.cmp(&b.md5))
}

fn hex_md5(md5: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in md5 {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn stored_binary_path(meta: &BinaryMeta) -> &str {
    if !meta.basename.is_empty() {
        meta.basename.as_str()
    } else {
        meta.origin_token.as_str()
    }
}

fn fmt_num(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn fmt_duration(secs: f64) -> String {
    let secs = secs.max(0.0).round() as u64;
    let mins = secs / 60;
    let rem_secs = secs % 60;
    if mins > 0 {
        format!("{}m{:02}s", mins, rem_secs)
    } else {
        format!("{}s", rem_secs)
    }
}

fn progress_bar(pct: f64, width: usize) -> String {
    let filled = ((pct * width as f64).round() as usize).min(width);
    let mut bar = String::with_capacity(width + 2);
    bar.push('[');
    for idx in 0..width {
        bar.push(if idx < filled { '#' } else { '-' });
    }
    bar.push(']');
    bar
}

fn truncate_middle(input: &str, max_len: usize) -> String {
    let chars: Vec<char> = input.chars().collect();
    if chars.len() <= max_len {
        return input.to_string();
    }
    if max_len <= 3 {
        return chars.into_iter().take(max_len).collect();
    }
    let keep_left = (max_len - 3) / 2;
    let keep_right = max_len - 3 - keep_left;
    let left: String = chars.iter().take(keep_left).collect();
    let right: String = chars
        .iter()
        .skip(chars.len().saturating_sub(keep_right))
        .collect();
    format!("{}...{}", left, right,)
}

fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        let escaped = field.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        field.to_string()
    }
}

fn main() -> io::Result<()> {
    let args = parse_args()?;
    let config_path = args.config_path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("non-utf8 config path: {}", args.config_path.display()),
        )
    })?;

    let cfg = Config::load(config_path)?;
    let rt = EngineRuntime::open_for_replay(cfg.engine.clone(), cfg.scoring.clone())?;

    if let Some(parent) = args.output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut binaries = rt.ctx_index.list_binary_metas()?;
    binaries.sort_by(cmp_binary_meta);
    let total_rows_estimate: u64 = binaries.iter().map(|meta| meta.function_count).sum();

    let file = File::create(&args.output_path)?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "function_hash,binary_id,binary_path")?;

    println!("Exporting function-to-binary CSV");
    println!("  Config: {}", args.config_path.display());
    println!("  Output: {}", args.output_path.display());
    println!("  Binaries: {}", fmt_num(binaries.len() as u64));
    println!("  Estimated rows: {}", fmt_num(total_rows_estimate));

    let mut progress = ExportProgress::new(binaries.len() as u64, total_rows_estimate);

    let mut row_count = 0u64;
    for meta in &binaries {
        let binary_id = hex_md5(&meta.md5);
        let display_path = stored_binary_path(meta);
        let binary_path = csv_escape(display_path);
        let keys = rt
            .ctx_index
            .get_binary_function_keys(&meta.md5, usize::MAX)?;
        for key in &keys {
            writeln!(writer, "{key:032x},{binary_id},{binary_path}")?;
            row_count += 1;
        }
        progress.advance(keys.len() as u64, display_path, false);
    }
    writer.flush()?;
    progress.finish();

    println!(
        "Wrote {} rows across {} binaries to {}",
        row_count,
        binaries.len(),
        args.output_path.display()
    );
    println!("binary_path uses the stored basename field (full original paths are not persisted)");

    Ok(())
}
