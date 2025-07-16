//! Enhanced Orchestrator Client
//! 
//! 对原始OrchestratorClient的包装，添加高级错误处理和重试机制

use crate::environment::Environment;
use crate::orchestrator::OrchestratorClient;
use crate::nexus_orchestrator::orchestrator_client::OrchestratorClient as GrpcClient;
use crate::nexus_orchestrator::GetProofTaskRequest;
use crate::task::Task;
use sha3::Digest;
use std::collections::HashMap;
use std::sync::Mutex;
use log::{warn, debug};
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;

// 创建全局证明缓存
static PROOF_CACHE: Lazy<Mutex<HashMap<String, (Vec<u8>, String, usize)>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

/// 增强版协调器客户端 - 支持代理和证明缓存
pub struct EnhancedOrchestratorClient {
    pub client: OrchestratorClient,
    environment: Environment,
}

impl EnhancedOrchestratorClient {
    /// 创建新的增强版客户端
    pub fn new(environment: Environment) -> Self {
        Self {
            client: Self::create_default_client_with_env(environment.clone()),
            environment,
        }
    }

    /// 创建带代理的增强版客户端
    pub fn new_with_proxy(environment: Environment, proxy_file: Option<&str>) -> Self {
        if let Some(proxy_path) = proxy_file {
            // 尝试加载代理列表
            match std::fs::read_to_string(proxy_path) {
                Ok(content) => {
                    // 解析代理列表
                    let proxies: Vec<String> = content
                        .lines()
                        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
                        .map(|line| line.trim().to_string())
                        .collect();

                    if !proxies.is_empty() {
                        debug!("已加载 {} 个代理", proxies.len());
                        let client = Self::create_client_with_proxies(&proxies, environment.clone());
                        return Self {
                            client,
                            environment,
                        };
                    } else {
                        debug!("代理列表为空，使用默认客户端");
                        return Self {
                            client: Self::create_default_client_with_env(environment.clone()),
                            environment,
                        };
                    }
                }
                Err(_e) => {
                    debug!("无法读取代理文件，使用默认客户端");
                    return Self {
                        client: Self::create_default_client_with_env(environment.clone()),
                        environment,
                    };
                }
            }
        }

        // 如果没有提供代理文件，使用默认客户端
        Self {
            client: Self::create_default_client_with_env(environment.clone()),
            environment,
        }
    }

    /// 获取任务
    pub async fn get_task(&self, node_id: &str, verifying_key: &ed25519_dalek::VerifyingKey) -> Result<Task, Box<dyn std::error::Error + Send + Sync>> {
        self.client.get_proof_task(node_id, verifying_key).await
    }

    /// 提交证明
    pub async fn submit_proof(
        &self,
        task_id: &str,
        proof_hash: &str,
        proof_bytes: Vec<u8>,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 尝试提交证明
        let result = self.client.submit_proof(task_id, proof_hash, &proof_bytes, &signing_key).await;
        
        // 如果提交成功，从缓存中移除
        if result.is_ok() {
            let mut cache = PROOF_CACHE.lock().unwrap();
            cache.remove(task_id);
        }
        
        result
    }
    
    /// 缓存证明以便后续重试
    pub fn cache_proof(&self, task_id: &str, proof_hash: &str, proof_bytes: &[u8]) {
        let mut cache = PROOF_CACHE.lock().unwrap();
        
        // 检查是否已经存在该任务的缓存
        if let Some((_, _, attempts)) = cache.get(task_id) {
            // 如果已经存在，增加尝试次数
            cache.insert(task_id.to_string(), (proof_bytes.to_vec(), proof_hash.to_string(), attempts + 1));
        } else {
            // 如果不存在，添加到缓存
            cache.insert(task_id.to_string(), (proof_bytes.to_vec(), proof_hash.to_string(), 0));
        }
    }
    
    /// 获取缓存的证明
    pub fn get_cached_proof(&self, task_id: &str) -> Option<(Vec<u8>, String, usize)> {
        let cache = PROOF_CACHE.lock().unwrap();
        cache.get(task_id).cloned()
    }
    
    /// 清理缓存
    #[allow(dead_code)]
    pub fn clear_cache(&self) {
        let mut cache = PROOF_CACHE.lock().unwrap();
        cache.clear();
    }
    
    /// 获取当前缓存大小
    #[allow(dead_code)]
    pub fn cache_size(&self) -> usize {
        let cache = PROOF_CACHE.lock().unwrap();
        cache.len()
    }
    
    /// 创建默认客户端
    fn create_default_client_with_env(environment: Environment) -> OrchestratorClient {
        OrchestratorClient::new(environment)
    }
    
    /// 创建带代理的客户端
    fn create_client_with_proxies(proxies: &[String], environment: Environment) -> OrchestratorClient {
        // 随机选择一个代理
        let mut rng = rand::thread_rng();
        if let Some(proxy) = proxies.choose(&mut rng) {
            debug!("使用代理: {}", proxy);
            
            // 创建带代理的客户端
            match OrchestratorClient::new_with_proxy(environment, proxy) {
                Ok(client) => {
                    return client;
                }
                Err(e) => {
                    warn!("创建代理客户端失败: {}, 使用默认客户端", e);
                }
            }
        }
        
        // 如果没有可用的代理或创建失败，使用默认客户端
        OrchestratorClient::new(environment)
    }
} 