//! Application configuration.

use crate::environment::Environment;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{fs, path::Path};

/// Get the path to the Nexus config file, 优先从当前目录下的nexus.config读取，如果不存在则使用~/.nexus/config.json.
pub fn get_config_path() -> Result<PathBuf, std::io::Error> {
    // 先尝试当前目录下的nexus.config
    let local_config_path = std::env::current_dir()?.join("nexus.config");
    
    // 如果当前目录存在nexus.config文件，直接返回
    if local_config_path.exists() {
        return Ok(local_config_path);
    }
    
    // 否则使用原来的路径 ~/.nexus/config.json
    let home_path = home::home_dir().ok_or(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Home directory not found",
    ))?;
    let config_path = home_path.join(".nexus").join("config.json");
    Ok(config_path)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Environment
    #[serde(default)]
    pub environment: String,

    /// The unique identifier for the node, UUIDv4 format. Empty when not yet registered.
    #[serde(default)]
    pub user_id: String,

    /// The wallet address associated with the user, typically an Ethereum address. Empty when not yet registered.
    #[serde(default)]
    pub wallet_address: String,

    /// The node's unique identifier, probably an integer. Empty when not yet registered.
    #[serde(default)]
    pub node_id: String,
    
    /// 初始请求速率（每秒请求数）
    #[serde(default = "default_initial_rate")]
    pub initial_request_rate: f64,
    
    /// 最低请求速率（每秒请求数）
    #[serde(default = "default_min_rate")]
    pub min_request_rate: f64,
    
    /// 最高请求速率（每秒请求数）
    #[serde(default = "default_max_rate")]
    pub max_request_rate: f64,
}

fn default_initial_rate() -> f64 {
    1.0 // 默认每秒1个请求
}

fn default_min_rate() -> f64 {
    0.5 // 默认最低每秒0.5个请求（每2秒1个）
}

fn default_max_rate() -> f64 {
    10.0 // 默认最高每秒10个请求
}

impl Config {
    /// Create Config with the given node_id.
    pub fn new(
        user_id: String,
        wallet_address: String,
        node_id: String,
        environment: Environment,
    ) -> Self {
        Config {
            user_id,
            wallet_address,
            node_id,
            environment: environment.to_string(),
            initial_request_rate: default_initial_rate(),
            min_request_rate: default_min_rate(),
            max_request_rate: default_max_rate(),
        }
    }

    /// Loads configuration from a JSON file at the given path.
    ///
    /// # Errors
    /// Returns an `std::io::Error` if reading from file fails or JSON is invalid.
    pub fn load_from_file(path: &Path) -> Result<Self, std::io::Error> {
        let buf = fs::read(path)?;
        let config: Config = serde_json::from_slice(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    /// Saves the configuration to a JSON file at the given path.
    ///
    /// Directories will be created if they don't exist. This method overwrites existing files.
    ///
    /// # Errors
    /// Returns an `std::io::Error` if writing to file fails or serialization fails.
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Serialization failed: {}", e),
            )
        })?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Clear the node ID configuration file.
    pub fn clear_node_config(path: &Path) -> std::io::Result<()> {
        // Check that the path ends with config.json
        if !path.ends_with("config.json") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Path must end with config.json",
            ));
        }

        // If no file exists, return OK
        if !path.exists() {
            println!("No config file found at {}", path.display());
            return Ok(());
        }

        // If the file exists, remove it
        fs::remove_file(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    /// Helper function to create a test configuration.
    fn get_config() -> Config {
        Config {
            environment: "test".to_string(),
            user_id: "test_user_id".to_string(),
            wallet_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            node_id: "test_node_id".to_string(),
            initial_request_rate: default_initial_rate(),
            min_request_rate: default_min_rate(),
            max_request_rate: default_max_rate(),
        }
    }

    #[test]
    // Loading a saved configuration file should return the same configuration.
    fn test_load_recovers_saved_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");

        let config = get_config();
        config.save(&path).unwrap();

        let loaded_config = Config::load_from_file(&path).unwrap();
        assert_eq!(config, loaded_config);
    }

    #[test]
    // Saving a configuration should create directories if they don't exist.
    fn test_save_creates_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent_dir").join("config.json");
        let config = get_config();
        let result = config.save(&path);

        // Check if the directories were created
        assert!(result.is_ok(), "Failed to save config");
        assert!(
            path.parent().unwrap().exists(),
            "Parent directory does not exist"
        );
    }

    #[test]
    // Saving a configuration should overwrite an existing file.
    fn test_save_overwrites_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");

        // Create an initial config and save it
        let mut config1 = get_config();
        config1.user_id = "test_user_id".to_string();
        config1.save(&path).unwrap();

        // Create a new config and save it to the same path
        let mut config2 = get_config();
        config2.user_id = "new_test_user_id".to_string();
        config2.save(&path).unwrap();

        // Load the saved config and check if it matches the second one
        let loaded_config = Config::load_from_file(&path).unwrap();
        assert_eq!(config2, loaded_config);
    }

    #[test]
    // Loading an invalid JSON file should return an error.
    fn test_load_rejects_invalid_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("invalid_config.json");

        let mut file = File::create(&path).unwrap();
        writeln!(file, "invalid json").unwrap();

        let result = Config::load_from_file(&path);
        assert!(result.is_err());
    }

    #[test]
    // Clearing the node configuration file should remove it if it exists.
    fn test_clear_node_config_removes_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        let config = get_config();
        config.save(&path).unwrap();

        Config::clear_node_config(&path).unwrap();
        assert!(!path.exists(), "Config file was not removed");
    }

    #[test]
    // Should load JSON containing a user_id and empty strings for other fields.
    fn test_load_config_with_user_id_and_empty_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");

        // Write a JSON with user_id and empty strings for other fields
        let mut file = File::create(&path).unwrap();
        writeln!(file, r#"{{ "user_id": "test_user", "wallet_address": "", "environment": "", "node_id": "", "initial_request_rate": 1.0, "min_request_rate": 0.5, "max_request_rate": 10.0 }}"#).unwrap();

        match Config::load_from_file(&path) {
            Ok(config) => {
                // The user_id must be set correctly.
                assert_eq!(config.user_id, "test_user");
                // Other fields should be empty or default
                assert!(config.wallet_address.is_empty());
                assert!(config.environment.is_empty());
                assert!(config.node_id.is_empty());
                assert_eq!(config.initial_request_rate, 1.0);
                assert_eq!(config.min_request_rate, 0.5);
                assert_eq!(config.max_request_rate, 10.0);
            }
            Err(e) => {
                panic!("Failed to load config with user_id and empty fields: {}", e);
            }
        }
    }

    #[test]
    // (Backwards compatibility) Should load JSON containing only node_id.
    fn test_load_config_with_only_node_id() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");

        // Write a minimal JSON with only node_id
        let mut file = File::create(&path).unwrap();
        writeln!(file, r#"{{ "node_id": "12345" }}"#).unwrap();

        match Config::load_from_file(&path) {
            Ok(config) => {
                // The node_id must be set correctly.
                assert_eq!(config.node_id, "12345");
                // Other fields should be empty or default
                assert!(config.user_id.is_empty());
                assert!(config.wallet_address.is_empty());
                assert!(config.environment.is_empty());
                assert_eq!(config.initial_request_rate, default_initial_rate());
                assert_eq!(config.min_request_rate, default_min_rate());
                assert_eq!(config.max_request_rate, default_max_rate());
            }
            Err(e) => {
                panic!("Failed to load config with only node_id: {}", e);
            }
        }
    }

    #[test]
    // (Backwards compatibility) Should load JSON with node_id and empty strings for other fields.
    fn test_load_config_with_node_id_and_empty_strings() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");

        let config = Config {
            environment: "".to_string(),
            user_id: "".to_string(),
            wallet_address: "".to_string(),
            node_id: "12345".to_string(),
            initial_request_rate: default_initial_rate(),
            min_request_rate: default_min_rate(),
            max_request_rate: default_max_rate(),
        };
        config.save(&path).unwrap();

        match Config::load_from_file(&path) {
            Ok(config) => {
                // The node_id must be set correctly.
                assert_eq!(config.node_id, "12345");
                // Other fields should be empty or default
                assert!(config.user_id.is_empty());
                assert!(config.wallet_address.is_empty());
                assert!(config.environment.is_empty());
                assert_eq!(config.initial_request_rate, default_initial_rate());
                assert_eq!(config.min_request_rate, default_min_rate());
                assert_eq!(config.max_request_rate, default_max_rate());
            }
            Err(e) => {
                panic!("Failed to load config with only node_id: {}", e);
            }
        }
    }

    #[test]
    // Should ignore unexpected fields in the JSON.
    fn test_load_config_with_additional_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");

        // Write a JSON with additional fields
        let mut file = File::create(&path).unwrap();
        writeln!(file, r#"{{ "node_id": "12345", "extra_field": "value" }}"#).unwrap();

        match Config::load_from_file(&path) {
            Ok(config) => {
                // The node_id must be set correctly.
                assert_eq!(config.node_id, "12345");
                // Other fields should be empty or default
                assert!(config.user_id.is_empty());
                assert!(config.wallet_address.is_empty());
                assert!(config.environment.is_empty());
                assert_eq!(config.initial_request_rate, default_initial_rate());
                assert_eq!(config.min_request_rate, default_min_rate());
                assert_eq!(config.max_request_rate, default_max_rate());
            }
            Err(e) => {
                panic!("Failed to load config with additional fields: {}", e);
            }
        }
    }
}
