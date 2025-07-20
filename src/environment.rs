use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use clap::ValueEnum;
use ed25519_dalek::SigningKey;

/// 环境枚举
#[derive(Clone, Default, Copy, PartialEq, Eq, ValueEnum, Debug)]
pub enum EnvironmentType {
    /// Local development environment.
    Local,
    /// Staging environment for pre-production testing.
    Staging,
    /// Beta environment for limited user exposure.
    #[default]
    Beta,
}

/// 环境配置
#[derive(Clone, Debug)]
pub struct Environment {
    pub env_type: EnvironmentType,
    #[allow(dead_code)]
    pub api_url: String,
    #[allow(dead_code)]
    pub client_id: String,
    #[allow(dead_code)]
    pub namespace: String,
    #[allow(dead_code)]
    pub key_manager: SigningKey,
}

impl Environment {
    /// 获取与环境关联的orchestrator服务URL
    pub fn orchestrator_url(&self) -> String {
        match self.env_type {
            EnvironmentType::Local => "http://localhost:50505".to_string(),
            EnvironmentType::Staging => "https://staging.orchestrator.nexus.xyz".to_string(),
            EnvironmentType::Beta => "https://production.orchestrator.nexus.xyz".to_string(),
        }
    }
    
    /// 创建默认环境
    pub fn default() -> Self {
        // 生成一个临时密钥，通常会在setup过程中被替换
        let temp_key = SigningKey::generate(&mut rand::thread_rng());
        
        Self {
            env_type: EnvironmentType::Beta,
            api_url: "https://api.nexus.xyz".to_string(),
            client_id: String::new(),
            namespace: "default".to_string(),
            key_manager: temp_key,
        }
    }
    
    /// 创建特定类型的环境
    pub fn new(env_type: EnvironmentType) -> Self {
        let mut env = Self::default();
        env.env_type = env_type;
        env
    }
}

impl FromStr for Environment {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 尝试将字符串解析为EnvironmentType
        if let Ok(env_type) = s.parse::<EnvironmentType>() {
            Ok(Environment::new(env_type))
        } else {
            Err(())
        }
    }
}

impl FromStr for EnvironmentType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local" => Ok(EnvironmentType::Local),
            "staging" => Ok(EnvironmentType::Staging),
            "beta" => Ok(EnvironmentType::Beta),
            _ => Err(()),
        }
    }
}

impl Display for EnvironmentType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvironmentType::Local => write!(f, "Local"),
            EnvironmentType::Staging => write!(f, "Staging"),
            EnvironmentType::Beta => write!(f, "Beta"),
        }
    }
}

impl Display for Environment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.env_type)
    }
}
