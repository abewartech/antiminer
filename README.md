# Antiminer - Rust Anti-Crypto-Mining Daemon

High-performance, aggressive anti-mining daemon built in Rust for Linux servers.

## 📦 Components
*   **Daemon**: `/usr/local/bin/antiminer`
*   **Config**: `/etc/antiminer.toml`
*   **Service**: `/etc/systemd/system/antiminer.service`

## 🛠 Installation (Compiling from Source)

Since the target server is infected, copy the source from a clean machine or compile on a secure CI/CD and transfer the binary.

### 1. Build
```bash
# On a clean environment (due to high load on infected server)
cargo build --release
```

### 2. Deploy
Transfer `target/release/antiminer` to the server.

```bash
# Install Binary
cp target/release/antiminer /usr/local/bin/
chmod +x /usr/local/bin/antiminer

# Config
cp antiminer.toml /etc/antiminer.toml

# Service
cp antiminer.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now antiminer
```

## 🔒 Hardening & Logic

### Detection Logic
1.  **Regex Name**: `[A-Za-z0-9]{7,12}` + CPU > 70%
2.  **Location Check**: Any binary running from `/tmp`, `/var/tmp`, `/dev/shm`, `/run` is KILLED immediately.
3.  **Signature**: Scans `cmdline` for `xmrig`, `pool`, `stratum`.
4.  **Respawn Protection**: Hashes binaries. If a hash reappears, strict blocking applies.

### Actions Taken
When a miner is detected:
1.  **SIGKILL**: Immediate termination.
2.  **Sanitization**:
    *   File is deleted.
    *   Replaced with empty dummy file.
    *   `chattr +i` (Immutable bit) set to prevent overwrite.


## ⚠️ Notes & Bypass Mitigations

*   **Immutable Files**: The daemon uses `chattr +i`. To remove manually, run `chattr -i <file>` first.
*   **False Positives**: Add process names to `[whitelist]` in `/etc/antiminer.toml` and restart service.
*   **NoExec Support**: This tool is designed for systems where `/tmp` cannot be mounted `noexec`. It uses `inotify` and polling to emulate this security.

## 🛑 Emergency Stop
```bash
systemctl stop antiminer
```
