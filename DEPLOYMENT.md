# Antiminer Deployment Guide

This guide details how to deploy `antiminer` to a production Linux server, specifically one that may already be compromised or under high load.

## 📋 Prerequisites

*   **Target System**: Linux (Systemd based, e.g., Ubuntu, Debian, CentOS, RHEL).
*   **Build System**: A clean machine with Rust installed (`rustc`, `cargo`).
    *   *Note: It is safer to build on a clean machine than on an infected one.*

## 🚀 Step 1: Compilation

On your **clean build machine**:

1.  **Clone/Copy source code**:
    ```bash
    cd antiminer
    ```

2.  **Build Release Binary**:
    ```bash
    cargo build --release
    ```
    *   The output binary will be at: `target/release/antiminer`

3.  **Prepare for Transfer**:
    *   You will need to copy the following files to the target server:
        *   `target/release/antiminer` (The binary)
        *   `antiminer.toml` (Configuration)
        *   `antiminer.service` (Service definition)

## 📦 Step 2: Installation on Target Server

⚠️ **Root Privileges Required**: You must be root or use `sudo`.

1.  **Transfer Files**: SCP or copy the files to the server.

2.  **Install Binary**:
    ```bash
    # Stop existing service if running
    systemctl stop antiminer 2>/dev/null

    # Copy binary to system path
    cp antiminer /usr/local/bin/
    chmod +x /usr/local/bin/antiminer
    
    # Set owner to root
    chown root:root /usr/local/bin/antiminer
    ```

3.  **Install Configuration**:
    ```bash
    mkdir -p /etc/antiminer
    cp antiminer.toml /etc/antiminer.toml
    
    # Secure the config file (read-only for root)
    chmod 600 /etc/antiminer.toml
    ```
    *   *Edit `/etc/antiminer.toml` now if you need to whitelist specific processes.*

4.  **Install Systemd Service**:
    ```bash
    cp antiminer.service /etc/systemd/system/
    
    # Reload systemd to recognize new service
    systemctl daemon-reload
    ```

## 🔌 Step 3: Activation & Monitoring

1.  **Start the Service**:
    ```bash
    systemctl enable antiminer
    systemctl start antiminer
    ```

2.  **Verify Status**:
    ```bash
    systemctl status antiminer
    ```
    *   You should see `Active: active (running)`.

3.  **Check Logs**:
    The daemon logs to stdout/stderr, which systemd captures, and also configured to log to `/var/log/antiminer.log` (if configured in TOML).
    
    **View Systemd Logs**:
    ```bash
    journalctl -u antiminer -f
    ```
    
    **View Application Log**:
    ```bash
    tail -f /var/log/antiminer.log
    ```

## 🛡️ Step 4: Verification (Test Run)

To verify the system is working without waiting for a real attack:

1.  **Simulate a Miner**:
    Create a harmless process that matches the "Random Name + High CPU" heuristic.
    
    *   rename a high-load tool (like `stress` or `yes`) to a 10-char random string:
        ```bash
        cp /usr/bin/yes /tmp/Abc1234567
        ```
    *   Run it:
        ```bash
        /tmp/Abc1234567 > /dev/null &
        ```
    *   **Result**: 
        *   Within 5-10 seconds, the process should be KILLED.
        *   The file `/tmp/Abc1234567` should be deleted and replaced with a dummy.
        *   Logs should show `DETECTED SUSPECT`.

## 🆘 Troubleshooting

*   **"Permission Denied"**: properly `chmod +x` the binary.
*   **False Positives**:
    *   If a legitimate service (e.g., `java`, `node`) is being killed:
    *   Check logs for the `comm` (command name).
    *   Add that name to `whitelist.process_names` in `/etc/antiminer.toml`.
    *   Run `systemctl restart antiminer`.
*   **Network Blocking**:
    *   Check blocked IPs: `iptables -L OUTPUT -n`
