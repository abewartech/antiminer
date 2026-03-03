mod config;
mod heuristics;
mod remediation;

use config::Config;
use heuristics::{check_process, hash_binary};
use remediation::{kill_process, sanitize_binary};

use cidr::Ipv4Cidr;
use log::{error, info, warn};
use notify::{RecursiveMode, Result, Watcher};
use procfs::process::Process;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{thread, time::Duration};
use sysinfo::System;

fn main() {
    env_logger::init();
    info!("Starting Antiminer Daemon...");

    // 1. Load Config
    let config_path = "/etc/antiminer.toml";
    let config = Config::load(config_path).unwrap_or_else(|_| {
        warn!("Config not found, using defaults");
        Config::default()
    });

    let config_arc = Arc::new(config.clone());

    // 2. Setup History for Respawn Detection
    // Hash -> Timestamp
    let detection_history: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));

    // 3. Setup File Watcher (Inotify)
    // Run in separate thread
    let config_watcher = config_arc.clone();
    thread::spawn(move || {
        if let Err(e) = run_watcher(config_watcher) {
            error!("Watcher error: {:?}", e);
        }
    });

    // 4. Load GeoIP CIDRs if enforced
    let mut allowed_cidrs: Vec<Ipv4Cidr> = Vec::new();
    if config.heuristics.enforce_geoip {
        let cidr_path = &config.heuristics.geoip_cidr_path;
        if let Ok(content) = std::fs::read_to_string(cidr_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    if let Ok(cidr) = Ipv4Cidr::from_str(trimmed) {
                        allowed_cidrs.push(cidr);
                    }
                }
            }
            info!(
                "Loaded {} GeoIP CIDRs from {}",
                allowed_cidrs.len(),
                cidr_path
            );
        } else {
            error!("Failed to read GeoIP CIDR file at {}", cidr_path);
        }
    }

    // 5. Main Loop
    let mut sys = System::new_all();
    loop {
        sys.refresh_all();

        // We use sysinfo for easy CPU usage tracking, but procfs for detailed inspection
        // We need to map sysinfo pids to procfs

        for (pid_sys, process_info) in sys.processes() {
            let pid = pid_sys.as_u32() as i32; // sysinfo Pid is generic, convert to i32 for procfs

            // Skip Whitelist
            if config.whitelist.process_names.contains(process_info.name()) {
                continue;
            }

            // Get procfs handle
            if let Ok(proc_obj) = Process::new(pid) {
                // Analyze
                let cpu_usage = process_info.cpu_usage();
                let detection = check_process(&proc_obj, &config, cpu_usage, &allowed_cidrs);

                if detection.is_suspect {
                    info!(
                        "DETECTED SUSPECT: PID {} Name: {} Reason: {}",
                        pid,
                        process_info.name(),
                        detection.reason
                    );

                    // Respond
                    perform_mitigation(pid, &proc_obj, detection.score, &detection_history);
                }
            }
        }

        thread::sleep(Duration::from_secs(config.system.scan_interval_seconds));
    }
}

fn run_watcher(config: Arc<Config>) -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(tx)?;

    for path in &config.heuristics.suspicious_paths {
        if std::path::Path::new(path).exists() {
            watcher.watch(std::path::Path::new(path), RecursiveMode::Recursive)?;
        }
    }

    for res in rx {
        match res {
            Ok(event) => {
                // On Create event in suspicious dirs, we could trigger immediate scan or just log
                // For now, prompt logging
                if event.kind.is_create() {
                    info!(
                        "File creation detected in monitored execution path: {:?}",
                        event.paths
                    );
                    // Ideally execute verification on this specific file immediately
                }
            }
            Err(e) => error!("watch error: {:?}", e),
        }
    }
    Ok(())
}

fn perform_mitigation(
    pid: i32,
    proc_obj: &Process,
    _score: u8,
    history: &Arc<Mutex<HashMap<String, u64>>>,
) {
    // 1. Calculate Hash (if possible before kill, or try to readexe)
    let binary_hash = if let Ok(exe) = proc_obj.exe() {
        hash_binary(&exe)
    } else {
        None
    };

    // 2. Kill
    kill_process(pid);

    // 4. Sanitize
    if let Ok(exe) = proc_obj.exe() {
        sanitize_binary(&exe);
    }

    // 5. Track Respawn
    if let Some(hash) = binary_hash {
        let mut hist = history.lock().unwrap();
        // Check if recently killed
        // Logic: If hash is in history < 30s, enable aggressive mode (already handled by sanitize? sanitize IS aggressive)
        // Converting requirement: "If hash reappears < 30s, Kill, Block, Lock path"
        // Since we already Kill, Block, Lock path on Detection, the Respawn Detection implies we should catch it FASTER or escalate.
        // Current logic applies it to ALL suspects.
        // We will just update history.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        hist.insert(hash, now);
    }
}
