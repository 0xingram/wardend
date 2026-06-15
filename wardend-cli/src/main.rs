// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use wardend_proto::ModuleReport;

#[derive(Parser)]
#[command(name = "wardend", about = "Is my computer safe?")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all security modules and print a report.
    Scan {
        /// Show technical detail and remediation for each finding.
        #[arg(long)]
        verbose: bool,
        /// Emit raw JSON instead of the human-readable report.
        #[arg(long)]
        json: bool,
        /// Disable all network activity; use cached feeds only.
        #[arg(long)]
        offline: bool,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan {
            verbose,
            json,
            offline,
        } => cmd_scan(verbose, json, offline),
    }
}

fn cmd_scan(verbose: bool, json: bool, offline: bool) -> Result<()> {
    let core = find_core_binary()?;

    let mut cmd = Command::new(&core);
    cmd.arg("scan");
    if offline {
        cmd.arg("--offline");
    }
    // Propagate WARDEND_PLUGIN_DIR so core can find plugins in dev mode.
    if let Ok(plugin_dir) = std::env::var("WARDEND_PLUGIN_DIR") {
        cmd.env("WARDEND_PLUGIN_DIR", plugin_dir);
    }

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("launching wardend-core at {}", core.display()))?;

    if !output.status.success() {
        bail!(
            "wardend-core exited with status {}",
            output.status.code().unwrap_or(-1)
        );
    }

    let raw = std::str::from_utf8(&output.stdout).context("wardend-core output is not UTF-8")?;

    if json {
        print!("{raw}");
        return Ok(());
    }

    let reports: Vec<ModuleReport> =
        serde_json::from_str(raw).context("parsing wardend-core JSON output")?;

    let colour = std::io::stdout().is_terminal();
    if verbose {
        print!("{}", wardend_cli::render_verbose(&reports, colour));
    } else {
        print!("{}", wardend_cli::render_default(&reports, colour));
    }
    Ok(())
}

/// Locate the wardend-core binary.
///
/// Order of precedence:
/// 1. `WARDEND_CORE_BIN` env var (explicit override).
/// 2. Adjacent to the CLI binary (covers `cargo run`-style dev invocation).
/// 3. Installed path `/usr/lib/wardend/wardend-core`.
fn find_core_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("WARDEND_CORE_BIN") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("wardend-core");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    let installed = PathBuf::from("/usr/lib/wardend/wardend-core");
    if installed.exists() {
        return Ok(installed);
    }
    bail!(
        "wardend-core not found — run 'cargo build --workspace' first, \
         or set WARDEND_CORE_BIN to its path"
    )
}
