use crate::config::Config;
use procfs::process::Process;
use regex::Regex;
use std::path::Path;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;

lazy_static::lazy_static! {
    static ref NAME_REGEX: Regex = Regex::new(r"^[A-Za-z0-9]{7,12}$").unwrap();
}

pub struct DetectionResult {
    pub is_suspect: bool,
    pub reason: String,
    pub score: u8,
}

// -- Pure Logic Helpers for Testing --

pub fn is_suspicious_name_and_cpu(name: &str, cpu_usage: f32, cpu_threshold: f32, name_regex: &Regex) -> Option<String> {
    if name_regex.is_match(name) || name == "iptables-save" {
        if cpu_usage > cpu_threshold {
            return Some(format!("Suspicious name '{}' + High CPU ({:.2}%)", name, cpu_usage));
        }
    }
    None
}

pub fn is_blacklisted_path(path_str: &str, suspicious_paths: &[String]) -> Option<String> {
    for suspect_path in suspicious_paths {
        if path_str.starts_with(suspect_path) {
            return Some(format!("Binary executing from blacklisted path: {}", path_str));
        }
    }
    None
}

pub fn is_suspicious_cmdline(cmdline: &[String], signatures: &[String]) -> Option<String> {
    let joined_cmd = cmdline.join(" ");
    for sig in signatures {
        if joined_cmd.contains(sig) {
            return Some(format!("Cmdline contains suspicious signature: '{}'", sig));
        }
    }
    None
}

// -- Main Check Function --

pub fn check_process(process: &Process, config: &Config, cpu_usage: f32) -> DetectionResult {
    let mut score = 0;
    let mut reasons = Vec::new();

    // 1. Process Name Pattern & CPU
    if let Ok(stat) = process.stat() {
        if let Some(reason) = is_suspicious_name_and_cpu(&stat.comm, cpu_usage, config.heuristics.high_cpu_threshold, &NAME_REGEX) {
            score += 50;
            reasons.push(reason);
        }
    }

    // 2. Binary Location
    if let Ok(exe) = process.exe() {
        if let Some(path_str) = exe.to_str() {
            if let Some(reason) = is_blacklisted_path(path_str, &config.heuristics.suspicious_paths) {
                score += 100;
                reasons.push(reason);
            }
        }
    }

    // 3. Cmdline Signature
    if let Ok(cmdline) = process.cmdline() {
        if let Some(reason) = is_suspicious_cmdline(&cmdline, &config.heuristics.cmdline_signatures) {
             score += 80;
             reasons.push(reason);
        }
    }
    
    // Check if parent is 1 (init) for random names (often detached)
    if let Ok(stat) = process.stat() {
        if stat.ppid == 1 && score > 0 {
             reasons.push("Parent is init (1)".to_string());
             score += 10;
        }
    }

    DetectionResult {
        is_suspect: score >= 50, // Threshold
        reason: reasons.join("; "),
        score,
    }
}

// ... existing hash_binary ...

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HeuristicsConfig;

    #[test]
    fn test_name_regex_logic() {
        let regex = Regex::new(r"^[A-Za-z0-9]{7,12}$").unwrap();

        // Match
        assert!(is_suspicious_name_and_cpu("Abc12345", 80.0, 70.0, &regex).is_some());

        // Match iptables-save
        assert!(is_suspicious_name_and_cpu("iptables-save", 80.0, 70.0, &regex).is_some());
        
        // No Match (too short)
        assert!(is_suspicious_name_and_cpu("short", 80.0, 70.0, &regex).is_none());
        
        // No Match (Low CPU)
        assert!(is_suspicious_name_and_cpu("Abc12345", 10.0, 70.0, &regex).is_none());
    }

    #[test]
    fn test_path_logic() {
        let suspects = vec!["/tmp".to_string(), "/var/tmp".to_string()];

        assert!(is_blacklisted_path("/tmp/miner", &suspects).is_some());
        assert!(is_blacklisted_path("/var/tmp/x", &suspects).is_some());
        assert!(is_blacklisted_path("/usr/bin/bash", &suspects).is_none());
    }

    #[test]
    fn test_cmdline_logic() {
        let signatures = vec!["xmrig".to_string(), "stratum".to_string()];
        
        let cmd_bad = vec!["./miner".to_string(), "--url=stratum+tcp://pool".to_string()];
        assert!(is_suspicious_cmdline(&cmd_bad, &signatures).is_some());

        let cmd_good = vec!["vim".to_string(), "file.txt".to_string()];
        assert!(is_suspicious_cmdline(&cmd_good, &signatures).is_none());
    }
}

pub fn hash_binary(path: &Path) -> Option<String> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return None,
    };
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let count = match file.read(&mut buffer) {
            Ok(c) => c,
            Err(_) => return None,
        };
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Some(hex::encode(hasher.finalize()))
}
