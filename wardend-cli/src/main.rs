// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::IsTerminal as _;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use wardend_proto::ModuleReport;

use wardend_cli::CoreMode;

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
    let mode = wardend_cli::find_core()?;

    let mut cmd = match &mode {
        CoreMode::Dev(path) => {
            let mut c = Command::new(path);
            c.arg("scan");
            c
        }
        CoreMode::Production(path) => {
            let mut c = Command::new("pkexec");
            c.arg(path).arg("scan");
            c
        }
    };

    if offline {
        cmd.arg("--offline");
    }

    // Propagate WARDEND_PLUGIN_DIR so core can find plugins in dev mode.
    if let Ok(plugin_dir) = std::env::var("WARDEND_PLUGIN_DIR") {
        cmd.env("WARDEND_PLUGIN_DIR", plugin_dir);
    }

    let core_display = match &mode {
        CoreMode::Dev(p) | CoreMode::Production(p) => p.display().to_string(),
    };

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("launching wardend-core at {core_display}"))?;

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
