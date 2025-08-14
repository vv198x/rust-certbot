use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub name: String,
    pub webroot: String,
    #[serde(default)]
    pub proxy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    #[serde(default = "default_provider")]
    pub provider: String,
    pub email: String,
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub account_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatesConfig {
    pub path: String,
    pub backup_path: String,
    pub renewal_threshold_days: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default)]
    pub keepalive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")] 
    pub level: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub max_size: Option<String>,
    #[serde(default)]
    pub max_files: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub domains: Vec<DomainConfig>,
    pub acme: AcmeConfig,
    pub certificates: CertificatesConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

fn default_provider() -> String {
    "lets-encrypt".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

impl AppConfig {
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path_ref = path.as_ref();
        let raw = fs::read_to_string(path_ref)?;
        let mut cfg: AppConfig = toml::from_str(&raw)?;

        // Defensive defaults
        if cfg.logging.level.trim().is_empty() {
            cfg.logging.level = default_log_level();
        }
        Ok(cfg)
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }
}