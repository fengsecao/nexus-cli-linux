//! Key management for the Nexus Network client
//!
//! Handles Ed25519 signing keys for node authentication

use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// 获取密钥存储路径
pub fn get_key_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home_path = home::home_dir().ok_or("Failed to get home directory")?;
    let key_path = home_path.join(".nexus").join("node.key");
    
    // 确保目录存在
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    Ok(key_path)
}

/// 加载或生成签名密钥
pub fn load_or_generate_signing_key() -> Result<SigningKey, Box<dyn std::error::Error>> {
    let key_path = get_key_path()?;
    
    if key_path.exists() {
        // 尝试加载现有密钥
        match load_signing_key(&key_path) {
            Ok(key) => return Ok(key),
            Err(_) => {
                // 如果加载失败，删除损坏的文件并生成新密钥
                let _ = fs::remove_file(&key_path);
            }
        }
    }
    
    // 生成新密钥并保存
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    save_signing_key(&key_path, &signing_key)?;
    
    println!("🔑 Generated new signing key: {}", key_path.display());
    Ok(signing_key)
}

/// 从文件加载签名密钥
fn load_signing_key(path: &Path) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let key_bytes = fs::read(path)?;
    if key_bytes.len() != 32 {
        return Err("Invalid key file length".into());
    }
    
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    Ok(SigningKey::from_bytes(&key_array))
}

/// 保存签名密钥到文件
fn save_signing_key(path: &Path, signing_key: &SigningKey) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, signing_key.to_bytes())?;
    
    // 设置文件权限为只有所有者可读写 (600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }
    
    Ok(())
}

/// 获取密钥的公钥
#[allow(dead_code)]
pub fn get_verifying_key(signing_key: &SigningKey) -> VerifyingKey {
    signing_key.verifying_key()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_key_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.key");
        
        let original_key = SigningKey::generate(&mut rand::thread_rng());
        save_signing_key(&key_path, &original_key).unwrap();
        
        let loaded_key = load_signing_key(&key_path).unwrap();
        assert_eq!(original_key.to_bytes(), loaded_key.to_bytes());
    }
} 