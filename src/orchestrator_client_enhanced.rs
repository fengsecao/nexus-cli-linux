//! Enhanced Orchestrator Client
//! 
//! 对原始OrchestratorClient的包装，添加高级错误处理和重试机制

use crate::orchestrator::{OrchestratorClient, error::OrchestratorError, Orchestrator};
use crate::environment::Environment;
use crate::task::Task;
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::warn;
use std::time::{Duration, Instant};

/// 增强型Orchestrator客户端
pub struct EnhancedOrchestratorClient {
    client: OrchestratorClient,
    last_request_time: Instant,
}

impl EnhancedOrchestratorClient {
    /// 创建新的增强型客户端
    pub fn new(environment: Environment) -> Self {
        Self {
            client: OrchestratorClient::new(environment),
            last_request_time: Instant::now(),
        }
    }
    
    /// 获取内部环境
    pub fn environment(&self) -> &Environment {
        self.client.environment()
    }

    /// 获取证明任务 - 包含429错误处理
    pub async fn get_task(&self, node_id: &str, verifying_key: &VerifyingKey) -> Result<Task, OrchestratorError> {
        // 强制限制请求频率，避免触发速率限制
        self.enforce_rate_limit().await;
        
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
        
        // 在异常情况下进行多次重试
        let mut attempts = 0;
        let max_attempts = 3;
        
        loop {
            attempts += 1;
            match self.client.submit_proof(task_id, proof_hash, proof.clone(), signing_key.clone(), 1).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    match &e {
                        OrchestratorError::Http { status, message } => {
                            if *status == 429 || message.contains("RATE_LIMITED") {
                                return Err(OrchestratorError::Http { 
                                    status: 429, 
                                    message: "RATE_LIMITED: Too many requests".to_string() 
                                });
                            }
                            
                            // 对于可恢复的错误进行重试
                            if (*status == 500 || *status == 502 || *status == 503 || *status == 504) && attempts < max_attempts {
                                let wait_time = 2_u64.pow(attempts as u32);
                                warn!("服务器错误 ({}), 第{}次尝试失败，等待{}秒后重试...", status, attempts, wait_time);
                                tokio::time::sleep(Duration::from_secs(wait_time)).await;
                                continue;
                            }
                        },
                        _ => {}
                    }
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
} 