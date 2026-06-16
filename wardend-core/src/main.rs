// SPDX-License-Identifier: GPL-3.0-or-later

use wardend_core::Config;
use wardend_core::feeds::FeedManager;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(String::as_str);

    match subcommand {
        Some("scan") => {
            let offline = args.iter().any(|a| a == "--offline");
            cmd_scan(offline).await;
        }
        Some("feeds") => {
            let action = args.get(2).map(String::as_str);
            if action != Some("update") {
                eprintln!("usage: wardend-core feeds update");
                std::process::exit(1);
            }
            cmd_feeds_update();
        }
        _ => {
            eprintln!("usage: wardend-core <scan|feeds update> [--offline]");
            std::process::exit(1);
        }
    }
}

async fn cmd_scan(offline: bool) {
    let cfg = Config::load();
    // Allow WARDEND_PLUGIN_DIR to override the config value in dev mode.
    let cfg = if let Ok(dir) = std::env::var("WARDEND_PLUGIN_DIR") {
        Config {
            plugin_dir: std::path::PathBuf::from(dir),
            ..cfg
        }
    } else {
        cfg
    };

    let reports = wardend_core::run_scan(&cfg, offline).await;

    match serde_json::to_string(&reports) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("error: failed to serialise scan results: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_feeds_update() {
    let cfg = Config::load();
    let mgr = FeedManager::new(cfg.feed_dir.clone(), false);

    let errors = mgr.update_all();
    if errors.is_empty() {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}
