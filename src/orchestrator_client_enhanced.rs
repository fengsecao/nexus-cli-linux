//! Enhanced Orchestrator Client
//! 
//! 对原始OrchestratorClient的包装，添加高级错误处理和重试机制

use crate::orchestrator::{OrchestratorClient, error::OrchestratorError, Orchestrator};
use crate::environment::Environment;
use crate::task::Task;
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{warn, debug};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use nexus_sdk::stwo::seq::Proof;

/// 缓存的证明数据
#[derive(Clone)]
struct CachedProof {
    proof: Vec<u8>,
    proof_hash: String,
    timestamp: Instant,
    attempts: usize,
}

/// 增强型Orchestrator客户端
pub struct EnhancedOrchestratorClient {
    client: OrchestratorClient,
    last_request_time: Instant,
    environment: Environment,
    // 证明缓存 - 任务ID -> 缓存的证明
    proof_cache: Arc<Mutex<HashMap<String, CachedProof>>>,
}

impl EnhancedOrchestratorClient {
    /// 创建新的增强型协调器客户端
    pub fn new(environment: Environment) -> Self {
        Self {
            client: OrchestratorClient::new(environment.clone()),
            last_request_time: Instant::now(),
            environment,
            proof_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// 获取内部环境
    pub fn environment(&self) -> &Environment {
        &self.environment
    }

    /// 获取证明任务 - 包含429错误处理
    pub async fn get_task(&self, node_id: &str, verifying_key: &VerifyingKey) -> Result<Task, OrchestratorError> {
        // 强制限制请求频率，避免触发速率限制
        self.enforce_rate_limit().await;
        
        // 清理过期的缓存
        self.clean_expired_cache();
        
        match self.client.get_proof_task(node_id, *verifying_key).await {
            Ok(task) => Ok(task),
            Err(e) => {
                match &e {
                    OrchestratorError::Http { status, message } => {
                        if *status == 429 || message.contains("RATE_LIMITED") {
                            return Err(OrchestratorError::Http { 
                                status: 429, 
                                message: "RATE_LIMITED: Too many requests".to_string() 
                            });
                        }
                    },
                    _ => {}
                }
                Err(e)
            }
        }
    }
    
    /// 提交证明 - 包含429错误处理
    pub async fn submit_proof(
        &self,
        task_id: &str,
        proof_hash: &str,
        proof: Vec<u8>,
        signing_key: SigningKey,
    ) -> Result<(), OrchestratorError> {
        // 强制限制请求频率，避免触发速率限制
        self.enforce_rate_limit().await;
        
        // 缓存证明，以便将来重试
        self.cache_proof(task_id, proof_hash, &proof);
        
        // 在异常情况下进行多次重试
        let mut attempts = 0;
        let max_attempts = 5; // 增加到5次
        
        loop {
            attempts += 1;
            match self.client.submit_proof(task_id, proof_hash, proof.clone(), signing_key.clone(), 1).await {
                Ok(_) => {
                    // 成功后移除缓存
                    self.remove_cached_proof(task_id);
                    return Ok(());
                },
                Err(e) => {
                    match &e {
                        OrchestratorError::Http { status, message } => {
                            if *status == 429 || message.contains("RATE_LIMITED") {
                                // 更新缓存中的尝试次数
                                self.update_proof_attempts(task_id);
                                
                                // 对于429错误，我们直接返回，让上层处理重试
                                // 这样可以让上层实现更复杂的重试策略
                                return Err(OrchestratorError::Http { 
                                    status: 429, 
                                    message: "RATE_LIMITED: Too many requests".to_string() 
                                });
                            }
                            
                            // 对于409冲突（证明已提交）视为成功
                            if *status == 409 || message.contains("CONFLICT") || message.contains("already submitted") {
                                debug!("证明已被接受 (409): {}", message);
                                // 移除缓存
                                self.remove_cached_proof(task_id);
                                return Ok(());
                            }
                            
                            // 对于可恢复的错误进行重试
                            if (*status == 500 || *status == 502 || *status == 503 || *status == 504) && attempts < max_attempts {
                                let wait_time = 2_u64.pow(attempts as u32);
                                warn!("服务器错误 ({}), 第{}次尝试失败，等待{}秒后重试...", status, attempts, wait_time);
                                tokio::time::sleep(Duration::from_secs(wait_time)).await;
                                continue;
                            }
                            
                            // 对于其他HTTP错误，如果尝试次数未达上限，也进行重试
                            if attempts < max_attempts {
                                let wait_time = 1_u64.pow(attempts as u32);
                                warn!("HTTP错误 ({}), 第{}次尝试失败，等待{}秒后重试...", status, attempts, wait_time);
                                tokio::time::sleep(Duration::from_secs(wait_time)).await;
                                continue;
                            }
                        },
                        _ => {
                            // 对于网络错误，也尝试重试
                            if attempts < max_attempts {
                                let wait_time = 2_u64.pow(attempts as u32);
                                warn!("网络错误, 第{}次尝试失败，等待{}秒后重试...", attempts, wait_time);
                                tokio::time::sleep(Duration::from_secs(wait_time)).await;
                                continue;
                            }
                        }
                    }
                    // 更新缓存中的尝试次数
                    self.update_proof_attempts(task_id);
                    return Err(e);
                }
            }
        }
    }
    
    /// 强制执行速率限制
    async fn enforce_rate_limit(&self) {
        // 确保请求之间至少间隔300毫秒
        let min_interval = Duration::from_millis(300);
        let elapsed = self.last_request_time.elapsed();
        
        if elapsed < min_interval {
            let wait_time = min_interval - elapsed;
            tokio::time::sleep(wait_time).await;
        }
    }
    
    /// 获取带有签名的提交证明URL
    pub async fn submit_proof_with_signature(
        &self,
        task_id: &str,
        proof_hash: &str,
        proof: Vec<u8>,
        signing_key: SigningKey,
    ) -> Result<(), OrchestratorError> {
        self.submit_proof(task_id, proof_hash, proof, signing_key).await
    }
    
    /// 缓存证明数据 - 增加缓存时间到60分钟
    fn cache_proof(&self, task_id: &str, proof_hash: &str, proof: &[u8]) {
        let mut cache = self.proof_cache.lock().unwrap();
        cache.insert(task_id.to_string(), CachedProof {
            proof: proof.to_vec(),
            proof_hash: proof_hash.to_string(),
            timestamp: Instant::now(),
            attempts: 0,
        });
    }
    
    /// 获取缓存的证明数据
    pub fn get_cached_proof(&self, task_id: &str) -> Option<(Vec<u8>, String, usize)> {
        let cache = self.proof_cache.lock().unwrap();
        cache.get(task_id).map(|cached| {
            (cached.proof.clone(), cached.proof_hash.clone(), cached.attempts)
        })
    }
    
    /// 更新证明尝试次数
    fn update_proof_attempts(&self, task_id: &str) {
        let mut cache = self.proof_cache.lock().unwrap();
        if let Some(cached) = cache.get_mut(task_id) {
            cached.attempts += 1;
        }
    }
    
    /// 移除缓存的证明
    fn remove_cached_proof(&self, task_id: &str) {
        let mut cache = self.proof_cache.lock().unwrap();
        cache.remove(task_id);
    }
    
    /// 清理过期的缓存（超过60分钟）
    fn clean_expired_cache(&self) {
        let mut cache = self.proof_cache.lock().unwrap();
        let expiry = Duration::from_secs(60 * 60); // 60分钟
        cache.retain(|_, cached| cached.timestamp.elapsed() < expiry);
    }
} 