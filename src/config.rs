use serde_derive::Deserialize;
use std::fs;
use std::collections::HashSet;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub system: SystemConfig,
    pub heuristics: HeuristicsConfig,
    pub whitelist: WhitelistConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SystemConfig {
    pub scan_interval_seconds: u64,
    pub log_path: String,
    pub dummy_file_path: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HeuristicsConfig {
    pub high_cpu_threshold: f32,
    pub high_cpu_duration_seconds: u64,
    pub suspicious_paths: Vec<String>,
    pub cmdline_signatures: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct WhitelistConfig {
    pub process_names: HashSet<String>,
    pub users: HashSet<String>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Config {
            system: SystemConfig {
                scan_interval_seconds: 5,
                log_path: "/var/log/antiminer.log".to_string(),
                dummy_file_path: None,
            },
            heuristics: HeuristicsConfig {
                high_cpu_threshold: 70.0,
                high_cpu_duration_seconds: 10,
                suspicious_paths: vec![
                    "/tmp".to_string(),
                    "/var/tmp".to_string(),
                    "/dev/shm".to_string(),
                    "/run".to_string(),
                ],
                cmdline_signatures: vec![
                    "stratum".to_string(),
                    "xmrig".to_string(),
                    "monero".to_string(),
                    "pool".to_string(),
                    "wallet".to_string(),
                    "hashrate".to_string(),
                ],
            },
            whitelist: WhitelistConfig {
                process_names: HashSet::from([
                    "dockerd".to_string(),
                    "containerd".to_string(),
                    "kubelet".to_string(),
                    "postgres".to_string(),
                    "mysqld".to_string(),
                    "node".to_string(),
                    "pm2".to_string(),
                    "java".to_string(),
                    "systemd".to_string(),
                    "rsyslogd".to_string(),
                ]),
                users: HashSet::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.system.scan_interval_seconds, 5);
        assert!(config.heuristics.suspicious_paths.contains(&"/tmp".to_string()));
        assert!(config.whitelist.process_names.contains("dockerd"));
    }

    #[test]
    fn test_load_parse_error() {
        // Test parsing invalid TOML
        let result = toml::from_str::<Config>("invalid syntax");
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_parse() {
        let toml_str = r#"
            [system]
            scan_interval_seconds = 10
            log_path = "/var/log/test.log"

            [heuristics]
            high_cpu_threshold = 90.0
            high_cpu_duration_seconds = 5
            suspicious_paths = ["/opt/malware"]
            cmdline_signatures = ["miner"]

            [whitelist]
            process_names = ["good_app"]
            users = ["admin"]
        "#;
        
        let config: Config = toml::from_str(toml_str).expect("Should parse valid TOML");
        assert_eq!(config.system.scan_interval_seconds, 10);
        assert_eq!(config.heuristics.high_cpu_threshold, 90.0);
        assert!(config.whitelist.process_names.contains("good_app"));
    }
}
