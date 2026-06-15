// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(String::as_str);

    if subcommand != Some("scan") {
        eprintln!("usage: wardend-core scan [--offline]");
        std::process::exit(1);
    }

    let offline = args.iter().any(|a| a == "--offline");
    let plugin_dir = plugin_dir();

    let reports = wardend_core::run_scan(&plugin_dir, offline).await;

    match serde_json::to_string(&reports) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("error: failed to serialise scan results: {e}");
            std::process::exit(1);
        }
    }
}

fn plugin_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("WARDEND_PLUGIN_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from("/usr/lib/wardend/plugins")
}
