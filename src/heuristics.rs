use crate::config::Config;
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use cidr::Ipv4Cidr;
use procfs::process::{FDTarget, Process};
use sha2::{Digest, Sha256};

lazy_static::lazy_static! {
    static ref NAME_REGEX: Regex = Regex::new(r"^[A-Za-z0-9]{7,12}$").unwrap();
}

pub struct DetectionResult {
    pub is_suspect: bool,
    pub reason: String,
    pub score: u8,
}

// -- Pure Logic Helpers for Testing --

pub fn is_suspicious_name_and_cpu(
    name: &str,
    cpu_usage: f32,
    cpu_threshold: f32,
    name_regex: &Regex,
) -> Option<String> {
    if name_regex.is_match(name) || name == "iptables-save" {
        if cpu_usage > cpu_threshold {
            return Some(format!(
                "Suspicious name '{}' + High CPU ({:.2}%)",
                name, cpu_usage
            ));
        }
    }
    None
}

pub fn is_blacklisted_path(path_str: &str, suspicious_paths: &[String]) -> Option<String> {
    for suspect_path in suspicious_paths {
        if path_str.starts_with(suspect_path) {
            return Some(format!(
                "Binary executing from blacklisted path: {}",
                path_str
            ));
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

pub fn is_non_indonesian_ip(ip: IpAddr, allowed_cidrs: &[Ipv4Cidr]) -> Option<String> {
    if let IpAddr::V4(ipv4) = ip {
        // Skip local networks, loopback, private ranges, broadcast, etc.
        if ipv4.is_loopback()
            || ipv4.is_private()
            || ipv4.is_link_local()
            || ipv4.is_broadcast()
            || ipv4.is_documentation()
            || ipv4.is_unspecified()
        {
            return None;
        }

        let mut allowed = false;
        for cidr in allowed_cidrs {
            if cidr.contains(&ipv4) {
                allowed = true;
                break;
            }
        }

        if !allowed {
            return Some(format!("Connected to Non-Indonesian IP: {}", ipv4));
        }
    } else {
        // We only enforce on IPv4 for now, or consider all IPv6 from non-local as suspicious.
        // If IPv6 is not in ID CIDR (we don't have IPv6 ID CIDR loaded), just return suspicious if it's external.
        let ip6 = match ip {
            IpAddr::V6(v6) => v6,
            _ => unreachable!(),
        };
        if !ip6.is_loopback() && !ip6.is_unspecified() && (ip6.segments()[0] & 0xfe00) != 0xfc00 {
            // Not a local IPv6
            return Some(format!("Connected to IPv6 IP: {}", ip6)); // Or we can ignore IPv6.
        }
    }
    None
}

// -- Main Check Function --

pub fn check_process(
    process: &Process,
    config: &Config,
    cpu_usage: f32,
    allowed_cidrs: &[Ipv4Cidr],
) -> DetectionResult {
    let mut score = 0;
    let mut reasons = Vec::new();

    // 1. Process Name Pattern & CPU
    if let Ok(stat) = process.stat() {
        if let Some(reason) = is_suspicious_name_and_cpu(
            &stat.comm,
            cpu_usage,
            config.heuristics.high_cpu_threshold,
            &NAME_REGEX,
        ) {
            score += 50;
            reasons.push(reason);
        }
    }

    // 2. Binary Location
    if let Ok(exe) = process.exe() {
        if let Some(path_str) = exe.to_str() {
            if let Some(reason) = is_blacklisted_path(path_str, &config.heuristics.suspicious_paths)
            {
                score += 100;
                reasons.push(reason);
            }
        }
    }

    // 3. Cmdline Signature
    if let Ok(cmdline) = process.cmdline() {
        if let Some(reason) = is_suspicious_cmdline(&cmdline, &config.heuristics.cmdline_signatures)
        {
            score += 80;
            reasons.push(reason);
        }
    }

    // 4. GeoIP Enforce
    if config.heuristics.enforce_geoip {
        // Find process inodes
        let mut inodes = HashSet::new();
        if let Ok(fds) = process.fd() {
            for fd in fds.flatten() {
                if let FDTarget::Socket(inode) = fd.target {
                    inodes.insert(inode);
                }
            }
        }

        // Check TCP connections (IPv4)
        if let Ok(tcp_entries) = process.tcp() {
            for entry in tcp_entries {
                if inodes.contains(&entry.inode) {
                    // Check state (01 = Established, 02 = SynSent in kernel log, procfs has enum depending on version)
                    // Unfortunately procfs versions differ. We'll check if the remote port is non-zero
                    if entry.remote_address.port() != 0 {
                        if let Some(reason) = is_non_indonesian_ip(
                            IpAddr::V4(entry.remote_address.ip()),
                            allowed_cidrs,
                        ) {
                            score += 100;
                            reasons.push(reason);
                        }
                    }
                }
            }
        }

        // Check TCPv6 connections (IPv6)
        if let Ok(tcp6_entries) = process.tcp6() {
            for entry in tcp6_entries {
                if inodes.contains(&entry.inode) {
                    if entry.remote_address.port() != 0 {
                        if let Some(reason) = is_non_indonesian_ip(
                            IpAddr::V6(entry.remote_address.ip()),
                            allowed_cidrs,
                        ) {
                            score += 100;
                            reasons.push(reason);
                        }
                    }
                }
            }
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

        let cmd_bad = vec![
            "./miner".to_string(),
            "--url=stratum+tcp://pool".to_string(),
        ];
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
