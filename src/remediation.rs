use std::process::Command;
use std::path::Path;
use std::fs;
use procfs::process::Process;
use std::net::IpAddr;
use log::{info, warn, error};

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

pub fn block_network(pid: i32) {
    // Attempt to parse /proc/pid/net/tcp or udp to find foreign IPs
    // This is complex to do robustly in simple rust without a robust netstat parser, 
    // but we can look for ESTABLISHED connections.
    
    // For this implementation, we will use a simplified approach or placeholder 
    // because parsing /proc/net/tcp manually is verbose. 
    // However, the requirement is "Parse /proc/<pid>/net/tcp & udp, Ambil IP tujuan, Block via iptables"
    
    // We will read the file manually.
    if let Ok(p) = Process::new(pid) {
        if let Ok(tcp) = p.tcp() {
            for entry in tcp {
                // If checking foreign address
                 let remote_ip = entry.remote_address.ip();
                 if !is_whitelisted_ip(&remote_ip) {
                      add_iptables_drop(&remote_ip);
                 }
            }
        }
        if let Ok(udp) = p.udp() {
            for entry in udp {
                 let remote_ip = entry.remote_address.ip();
                 if !is_whitelisted_ip(&remote_ip) {
                      add_iptables_drop(&remote_ip);
                 }
            }
        }
    }
}

fn is_whitelisted_ip(ip: &IpAddr) -> bool {
    // Localhost, private networks, etc.
    // simplistic check
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback() || ipv4.is_private()
        },
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
        }
    }
}

fn add_iptables_drop(ip: &IpAddr) {
    let ip_str = ip.to_string();
    info!("BLOCKING IP: {}", ip_str);
    let _ = Command::new("iptables")
        .arg("-A")
        .arg("OUTPUT")
        .arg("-d")
        .arg(&ip_str)
        .arg("-j")
        .arg("DROP")
        .output();
}
