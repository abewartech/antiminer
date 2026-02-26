use std::process::Command;
use std::path::Path;
use std::fs;

use log::{info, warn};

pub fn kill_process(pid: i32) {
    info!("KILLING process {}", pid);
    // Use kill -9 via Command for reliability
    let _ = Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .output();
}

pub fn sanitize_binary(path: &Path) {
    let path_str = match path.to_str() {
        Some(s) => s,
        None => return,
    };

    info!("SANITIZING binary at {}", path_str);

    // 1. Remove binary
    if fs::remove_file(path).is_err() {
        warn!("Failed to remove file: {}", path_str);
    }

    // 2. Create dummy file
    if File::create(path).is_err() {
        warn!("Failed to create dummy file: {}", path_str);
    }

    // 3. chattr +i
    let _ = Command::new("chattr")
        .arg("+i")
        .arg(path_str)
        .output();
}

use std::fs::File;

