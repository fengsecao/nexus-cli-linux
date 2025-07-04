//! Nexus Orchestrator Client
//!
//! A client for the Nexus Orchestrator, allowing for proof task retrieval and submission.

use crate::environment::Environment;
use crate::nexus_orchestrator::{
    GetProofTaskRequest, GetProofTaskResponse, GetTasksRequest, GetTasksResponse, NodeType,
    RegisterNodeRequest, RegisterNodeResponse, RegisterUserRequest, SubmitProofRequest,
    UserResponse,
};
use crate::orchestrator::Orchestrator;
use crate::orchestrator::error::OrchestratorError;
use crate::system::{estimate_peak_gflops, get_memory_info};
use crate::task::Task;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use prost::Message;
use reqwest::{Client, ClientBuilder, Response, Proxy};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use rand::seq::SliceRandom;
use rand::thread_rng;
use log::{info, warn, error};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use crate::consts;

// Privacy-preserving country detection for network optimization.
// Only stores 2-letter country codes (e.g., "US", "CA", "GB") to help route
// requests to the nearest Nexus network servers for better performance.
// No precise location, IP addresses, or personal data is collected or stored.
static COUNTRY_CODE: OnceCell<String> = OnceCell::new();

/// 代理信息结构
#[derive(Clone, Debug)]
struct ProxyInfo {
    url: String,
    username: String,
    password: String,
    country: String,
}

/// 节点代理状态管理
#[derive(Debug)]
struct NodeProxyState {
    /// 存储节点ID到代理的映射关系
    node_proxies: Mutex<HashMap<String, ProxyInfo>>,
    /// 记录节点连续失败次数
    failure_counts: Mutex<HashMap<String, usize>>,
}

impl NodeProxyState {
    /// 创建新的节点代理状态管理器
    pub fn new() -> Self {
        Self {
            node_proxies: Mutex::new(HashMap::new()),
            failure_counts: Mutex::new(HashMap::new()),
        }
    }

    /// 获取节点的代理
    pub fn get_proxy(&self, node_id: &str) -> Option<ProxyInfo> {
        let proxies = self.node_proxies.lock().unwrap();
        proxies.get(node_id).cloned()
    }

    /// 设置节点的代理
    pub fn set_proxy(&self, node_id: &str, proxy: ProxyInfo) {
        let mut proxies = self.node_proxies.lock().unwrap();
        proxies.insert(node_id.to_string(), proxy);
    }

    /// 增加节点的失败次数
    pub fn increment_failure(&self, node_id: &str) -> usize {
        let mut counts = self.failure_counts.lock().unwrap();
        let count = counts.entry(node_id.to_string()).or_insert(0);
        *count += 1;
        *count
    }

    /// 重置节点的失败次数
    pub fn reset_failure(&self, node_id: &str) {
        let mut counts = self.failure_counts.lock().unwrap();
        counts.insert(node_id.to_string(), 0);
    }
}

/// 代理管理器
#[derive(Debug)]
struct ProxyManager {
    proxies: Arc<Mutex<Vec<ProxyInfo>>>,
}

impl ProxyManager {
    /// 创建新的代理管理器
    pub fn new() -> Self {
        Self {
            proxies: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 从文件加载代理列表
    pub fn load_from_file(&self, file_path: &str) -> io::Result<()> {
        info!("开始加载代理文件: {}", file_path);
        let path = Path::new(file_path);
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                error!("打开代理文件失败: {} - {}", file_path, e);
                return Err(e);
            }
        };
        
        let reader = io::BufReader::new(file);
        let mut proxies = Vec::new();
        let mut line_count = 0;
        let mut _valid_count = 0;  // 添加下划线前缀

        for line in reader.lines() {
            line_count += 1;
            if let Ok(line) = line {
                if line.trim().is_empty() || line.starts_with('#') {
                    continue;
                }

                // 解析格式: host:port:username:password
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 4 {
                    let host = parts[0];
                    let port = parts[1];
                    let username = parts[2];
                    
                    // 第四部分及之后的所有内容都作为密码
                    // 重新组合第四部分及之后的所有内容（如果有的话）
                    let password = if parts.len() > 4 {
                        // 如果有多个冒号，重新组合第四部分及之后的所有内容
                        parts[3..].join(":")
                    } else {
                        // 只有四部分，直接使用第四部分
                        parts[3].to_string()
                    };
                    
                    // 尝试从密码中解析国家信息，但不改变密码本身
                    let country = if password.contains("_country-") {
                        // 如果密码包含国家信息，提取出来用于显示
                        let parts: Vec<&str> = password.split("_country-").collect();
                        if parts.len() > 1 && !parts[1].is_empty() {
                            parts[1].to_string()
                        } else {
                            "UNKNOWN".to_string()
                        }
                    } else {
                        "UNKNOWN".to_string()
                    };
                    
                    // 使用HTTP协议
                    let url = format!("http://{}:{}", host, port);
                    
                    proxies.push(ProxyInfo {
                        url,
                        username: username.to_string(),
                        password,
                        country,
                    });
                    _valid_count += 1;
                } else {
                    warn!("代理格式错误 (行 {}): {}", line_count, line);
                }
            }
        }

        // 更新代理列表
        if !proxies.is_empty() {
            let mut proxy_list = self.proxies.lock().unwrap();
            *proxy_list = proxies;
            info!("已加载 {} 个代理 (总行数: {})", proxy_list.len(), line_count);
            Ok(())
        } else {
            let err = io::Error::new(io::ErrorKind::InvalidData, "代理文件为空或格式不正确");
            error!("代理文件无效: {} - 没有找到有效代理", file_path);
            Err(err)
        }
    }

    /// 获取下一个代理
    pub fn next_proxy(&self) -> Option<ProxyInfo> {
        let proxies = self.proxies.lock().unwrap();
        if proxies.is_empty() {
            warn!("代理列表为空");
            return None;
        }

        // 随机选择一个代理
        let mut rng = thread_rng();
        let selected = proxies.choose(&mut rng).cloned();
        
        if selected.is_none() {
            warn!("无法从代理列表中选择代理");
        }
        
        selected
    }
}

#[derive(Debug, Clone)]
pub struct OrchestratorClient {
    #[allow(dead_code)]
    client: Client,
    environment: Environment,
    proxy_manager: Arc<ProxyManager>,
    node_proxy_state: Arc<NodeProxyState>,
}

impl OrchestratorClient {
    /// Create a new orchestrator client with the given environment.
    pub fn new(environment: Environment) -> Self {
        let proxy_manager = Arc::new(ProxyManager::new());
        
        // 尝试加载默认代理文件
        if let Err(e) = proxy_manager.load_from_file("proxy.txt") {
            warn!("无法加载默认代理文件: {}", e);
        }
        
        Self {
            client: ClientBuilder::new()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            environment,
            proxy_manager,
            node_proxy_state: Arc::new(NodeProxyState::new()),
        }
    }

    /// Create a new orchestrator client with proxy support
    pub fn new_with_proxy(environment: Environment, proxy_file: Option<&str>) -> Self {
        let proxy_manager = Arc::new(ProxyManager::new());
        
        // 尝试加载指定的代理文件
        if let Some(file_path) = proxy_file {
            info!("尝试加载指定代理文件: {}", file_path);
            // 检查文件是否存在
            if !Path::new(file_path).exists() {
                warn!("指定的代理文件不存在: {}", file_path);
            } else {
                match proxy_manager.load_from_file(file_path) {
                    Ok(_) => info!("成功加载代理文件: {}", file_path),
                    Err(e) => warn!("无法加载代理文件 {}: {}", file_path, e),
                }
            }
        } else {
            // 尝试加载默认代理文件
            let default_path = "proxy.txt";
            if Path::new(default_path).exists() {
                info!("尝试加载默认代理文件: {}", default_path);
                match proxy_manager.load_from_file(default_path) {
                    Ok(_) => info!("成功加载默认代理文件"),
                    Err(e) => warn!("无法加载默认代理文件: {}", e),
                }
            } else {
                warn!("默认代理文件不存在: {}", default_path);
            }
        }
        
        Self {
            client: ClientBuilder::new()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            environment,
            proxy_manager,
            node_proxy_state: Arc::new(NodeProxyState::new()),
        }
    }

    fn build_url(&self, endpoint: &str) -> String {
        format!(
            "{}/{}",
            self.environment.orchestrator_url().trim_end_matches('/'),
            endpoint.trim_start_matches('/')
        )
    }

    fn encode_request<T: Message>(request: &T) -> Vec<u8> {
        request.encode_to_vec()
    }

    fn decode_response<T: Message + Default>(bytes: &[u8]) -> Result<T, OrchestratorError> {
        T::decode(bytes).map_err(OrchestratorError::Decode)
    }

    async fn handle_response_status(response: Response) -> Result<Response, OrchestratorError> {
        if !response.status().is_success() {
            return Err(OrchestratorError::from_response(response).await);
        }
        Ok(response)
    }

    /// 获取或分配节点的代理
    fn get_or_assign_proxy(&self, node_id: &str) -> Option<ProxyInfo> {
        // 先尝试获取已分配的代理
        if let Some(proxy) = self.node_proxy_state.get_proxy(node_id) {
            info!("节点 {} 使用已分配的代理: {} ({})", node_id, proxy.url, proxy.country);
            return Some(proxy);
        }
        
        // 如果没有分配过代理，随机分配一个
        if let Some(proxy) = self.proxy_manager.next_proxy() {
            info!("为节点 {} 分配新代理: {} ({})", node_id, proxy.url, proxy.country);
            self.node_proxy_state.set_proxy(node_id, proxy.clone());
            return Some(proxy);
        }
        
        warn!("无法为节点 {} 分配代理", node_id);
        None
    }
    
    /// 为节点更换代理
    fn replace_proxy(&self, node_id: &str) -> Option<ProxyInfo> {
        if let Some(proxy) = self.proxy_manager.next_proxy() {
            info!("为节点 {} 更换代理: {} ({})", node_id, proxy.url, proxy.country);
            self.node_proxy_state.set_proxy(node_id, proxy.clone());
            return Some(proxy);
        }
        
        warn!("无法为节点 {} 更换代理", node_id);
        None
    }

    /// 创建带有代理的HTTP客户端（使用指定代理）
    async fn create_client_with_proxy_info(&self, proxy_info: &ProxyInfo) -> Client {
        info!("使用代理: {} ({})", proxy_info.url, proxy_info.country);
        
        // 创建代理
        match Proxy::all(&proxy_info.url) {
            Ok(proxy) => {
                let proxy_with_auth = proxy.basic_auth(&proxy_info.username, &proxy_info.password);
                // 创建新的builder实例
                let builder = ClientBuilder::new()
                    .timeout(Duration::from_secs(15))  // 增加超时时间
                    .proxy(proxy_with_auth);
                
                match builder.build() {
                    Ok(client) => {
                        return client;
                    }
                    Err(e) => {
                        error!("创建代理客户端失败: {} - {}", proxy_info.url, e);
                    }
                }
            }
            Err(e) => {
                error!("创建代理失败: {} - {}", proxy_info.url, e);
            }
        }
        
        // 如果创建代理客户端失败，使用默认客户端
        info!("使用默认连接（无代理）");
        ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client")
    }

    /// 创建带有代理的HTTP客户端（基于节点ID）
    async fn create_client_with_node_proxy(&self, node_id: &str) -> Client {
        // 尝试获取或分配代理
        if let Some(proxy_info) = self.get_or_assign_proxy(node_id) {
            return self.create_client_with_proxy_info(&proxy_info).await;
        }
        
        // 如果没有可用代理，使用默认客户端
        info!("节点 {} 没有可用代理，使用默认连接", node_id);
        ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client")
    }

    /// 检查是否是需要重试的错误（如429或网络错误）
    fn is_retryable_error(&self, error: &OrchestratorError) -> bool {
        match error {
            OrchestratorError::Http { status, message: _ } => {
                // 检查是否是429错误
                if *status == reqwest::StatusCode::TOO_MANY_REQUESTS.as_u16() {
                    return true;
                }
                
                // 检查是否是网络连接错误（这里无法直接检查，因为HTTP错误已经被封装）
                false
            }
            OrchestratorError::Reqwest(e) => {
                // 检查是否是网络连接错误
                e.is_connect() || e.is_timeout()
            }
            _ => false,
        }
    }

    /// 计算退避时间
    /// 如果是429错误，使用配置的超时时间（带随机浮动）
    fn is_429_error(&self, error: &OrchestratorError) -> bool {
        match error {
            OrchestratorError::Http { status, message: _ } => {
                *status == reqwest::StatusCode::TOO_MANY_REQUESTS.as_u16()
            }
            _ => false,
        }
    }

    /// 带重试的GET请求
    async fn get_request_with_retry<T: Message + Default>(
        &self,
        endpoint: &str,
        body: Vec<u8>,
        node_id: &str,
    ) -> Result<T, OrchestratorError> {
        const MAX_RETRIES: usize = 3;
        let url = self.build_url(endpoint);
        
        // 初始尝试
        let mut result = self.execute_get_request::<T>(&url, body.clone(), node_id).await;
        
        // 如果成功，重置失败计数并返回结果
        if result.is_ok() {
            self.node_proxy_state.reset_failure(node_id);
            return result;
        }
        
        // 如果是可重试的错误，进行重试
        let mut retry_count = 0;
        while retry_count < MAX_RETRIES {
            let error = result.as_ref().err().unwrap();
            
            if !self.is_retryable_error(error) {
                // 如果不是可重试的错误，直接返回
                break;
            }
            
            // 增加失败计数
            let failure_count = self.node_proxy_state.increment_failure(node_id);
            
            // 检查是否有可用代理
            let has_proxy = self.node_proxy_state.get_proxy(node_id).is_some();
            
            // 如果有代理，尝试更换代理
            if has_proxy {
                self.replace_proxy(node_id);
            }
            
            // 检查是否是429错误
            let is_429 = self.is_429_error(error);
            
            let backoff_time = if is_429 {
                // 使用配置的429超时时间（带±10%随机浮动）
                consts::get_retry_timeout()
            } else if !has_proxy || failure_count > 1 {
                // 对于其他错误，使用指数退避
                std::cmp::min(2u64.pow((failure_count - 1) as u32), 30)
            } else {
                0
            };
            
            if backoff_time > 0 {
                info!("节点 {} 请求失败{}, 等待 {}s 后重试", 
                      node_id, 
                      if is_429 { " (429 Too Many Requests)" } else { "" }, 
                      backoff_time);
                tokio::time::sleep(Duration::from_secs(backoff_time)).await;
            } else {
                info!("节点 {} 请求失败，立即重试", node_id);
            }
            
            // 重试请求
            result = self.execute_get_request::<T>(&url, body.clone(), node_id).await;
            
            // 如果成功，重置失败计数并返回结果
            if result.is_ok() {
                self.node_proxy_state.reset_failure(node_id);
                return result;
            }
            
            retry_count += 1;
        }
        
        // 所有重试都失败，返回最后一次的错误
        result
    }
    
    /// 执行GET请求
    async fn execute_get_request<T: Message + Default>(
        &self,
        url: &str,
        body: Vec<u8>,
        node_id: &str,
    ) -> Result<T, OrchestratorError> {
        // 使用节点的代理客户端
        let client = self.create_client_with_node_proxy(node_id).await;
        
        let response = client
            .get(url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        let response = Self::handle_response_status(response).await?;
        let response_bytes = response.bytes().await?;
        Self::decode_response(&response_bytes)
    }

    /// 带重试的POST请求
    async fn post_request_with_retry<T: Message + Default>(
        &self,
        endpoint: &str,
        body: Vec<u8>,
        node_id: &str,
    ) -> Result<T, OrchestratorError> {
        const MAX_RETRIES: usize = 3;
        let url = self.build_url(endpoint);
        
        // 初始尝试
        let mut result = self.execute_post_request::<T>(&url, body.clone(), node_id).await;
        
        // 如果成功，重置失败计数并返回结果
        if result.is_ok() {
            self.node_proxy_state.reset_failure(node_id);
            return result;
        }
        
        // 如果是可重试的错误，进行重试
        let mut retry_count = 0;
        while retry_count < MAX_RETRIES {
            let error = result.as_ref().err().unwrap();
            
            if !self.is_retryable_error(error) {
                // 如果不是可重试的错误，直接返回
                break;
            }
            
            // 增加失败计数
            let failure_count = self.node_proxy_state.increment_failure(node_id);
            
            // 检查是否有可用代理
            let has_proxy = self.node_proxy_state.get_proxy(node_id).is_some();
            
            // 如果有代理，尝试更换代理
            if has_proxy {
                self.replace_proxy(node_id);
            }
            
            // 检查是否是429错误
            let is_429 = self.is_429_error(error);
            
            let backoff_time = if is_429 {
                // 使用配置的429超时时间（带±10%随机浮动）
                consts::get_retry_timeout()
            } else if !has_proxy || failure_count > 1 {
                // 对于其他错误，使用指数退避
                std::cmp::min(2u64.pow((failure_count - 1) as u32), 30)
            } else {
                0
            };
            
            if backoff_time > 0 {
                info!("节点 {} 请求失败{}, 等待 {}s 后重试", 
                      node_id, 
                      if is_429 { " (429 Too Many Requests)" } else { "" }, 
                      backoff_time);
                tokio::time::sleep(Duration::from_secs(backoff_time)).await;
            } else {
                info!("节点 {} 请求失败，立即重试", node_id);
            }
            
            // 重试请求
            result = self.execute_post_request::<T>(&url, body.clone(), node_id).await;
            
            // 如果成功，重置失败计数并返回结果
            if result.is_ok() {
                self.node_proxy_state.reset_failure(node_id);
                return result;
            }
            
            retry_count += 1;
        }
        
        // 所有重试都失败，返回最后一次的错误
        result
    }
    
    /// 执行POST请求
    async fn execute_post_request<T: Message + Default>(
        &self,
        url: &str,
        body: Vec<u8>,
        node_id: &str,
    ) -> Result<T, OrchestratorError> {
        // 使用节点的代理客户端
        let client = self.create_client_with_node_proxy(node_id).await;
        
        let response = client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        let response = Self::handle_response_status(response).await?;
        let response_bytes = response.bytes().await?;
        Self::decode_response(&response_bytes)
    }

    /// 带重试的POST请求（无响应）
    async fn post_request_no_response_with_retry(
        &self,
        endpoint: &str,
        body: Vec<u8>,
        node_id: &str,
    ) -> Result<(), OrchestratorError> {
        const MAX_RETRIES: usize = 3;
        let url = self.build_url(endpoint);
        
        // 初始尝试
        let mut result = self.execute_post_request_no_response(&url, body.clone(), node_id).await;
        
        // 如果成功，重置失败计数并返回结果
        if result.is_ok() {
            self.node_proxy_state.reset_failure(node_id);
            return result;
        }
        
        // 如果是可重试的错误，进行重试
        let mut retry_count = 0;
        while retry_count < MAX_RETRIES {
            let error = result.as_ref().err().unwrap();
            
            if !self.is_retryable_error(error) {
                // 如果不是可重试的错误，直接返回
                break;
            }
            
            // 增加失败计数
            let failure_count = self.node_proxy_state.increment_failure(node_id);
            
            // 检查是否有可用代理
            let has_proxy = self.node_proxy_state.get_proxy(node_id).is_some();
            
            // 如果有代理，尝试更换代理
            if has_proxy {
                self.replace_proxy(node_id);
            }
            
            // 检查是否是429错误
            let is_429 = self.is_429_error(error);
            
            let backoff_time = if is_429 {
                // 使用配置的429超时时间（带±10%随机浮动）
                consts::get_retry_timeout()
            } else if !has_proxy || failure_count > 1 {
                // 对于其他错误，使用指数退避
                std::cmp::min(2u64.pow((failure_count - 1) as u32), 30)
            } else {
                0
            };
            
            if backoff_time > 0 {
                info!("节点 {} 请求失败{}, 等待 {}s 后重试", 
                      node_id, 
                      if is_429 { " (429 Too Many Requests)" } else { "" }, 
                      backoff_time);
                tokio::time::sleep(Duration::from_secs(backoff_time)).await;
            } else {
                info!("节点 {} 请求失败，立即重试", node_id);
            }
            
            // 重试请求
            result = self.execute_post_request_no_response(&url, body.clone(), node_id).await;
            
            // 如果成功，重置失败计数并返回结果
            if result.is_ok() {
                self.node_proxy_state.reset_failure(node_id);
                return result;
            }
            
            retry_count += 1;
        }
        
        // 所有重试都失败，返回最后一次的错误
        result
    }
    
    /// 执行POST请求（无响应）
    async fn execute_post_request_no_response(
        &self,
        url: &str,
        body: Vec<u8>,
        node_id: &str,
    ) -> Result<(), OrchestratorError> {
        // 使用节点的代理客户端
        let client = self.create_client_with_node_proxy(node_id).await;
        
        let response = client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        Self::handle_response_status(response).await?;
        Ok(())
    }

    fn create_signature(
        &self,
        signing_key: &SigningKey,
        task_id: &str,
        proof_hash: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let signature_version = 0;
        let msg = format!("{} | {} | {}", signature_version, task_id, proof_hash);
        let signature = signing_key.sign(msg.as_bytes());
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        (
            signature.to_bytes().to_vec(),
            verifying_key.to_bytes().to_vec(),
        )
    }

    /// Detects the user's country for network optimization purposes.
    ///
    /// Privacy Note: This only detects the country (2-letter code like "US", "CA", "GB")
    /// and does NOT track precise location, IP address, or any personally identifiable
    /// information. The country information helps the Nexus network route requests to
    /// the nearest servers for better performance and reduced latency.
    ///
    /// The detection is cached for the duration of the program run.
    async fn get_country(&self) -> String {
        if let Some(country) = COUNTRY_CODE.get() {
            return country.clone();
        }

        let country = self.detect_country().await;
        let _ = COUNTRY_CODE.set(country.clone());
        country
    }

    async fn detect_country(&self) -> String {
        // Try Cloudflare first (most reliable)
        if let Ok(country) = self.get_country_from_cloudflare().await {
            return country;
        }

        // Fallback to ipinfo.io
        if let Ok(country) = self.get_country_from_ipinfo().await {
            return country;
        }

        // If we can't detect the country, use the US as a fallback
        "US".to_string()
    }

    async fn get_country_from_cloudflare(&self) -> Result<String, Box<dyn std::error::Error>> {
        // 使用默认客户端
        let client = self.get_default_client().await;
        
        let response = client
            .get("https://cloudflare.com/cdn-cgi/trace")
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let text = response.text().await?;

        for line in text.lines() {
            if let Some(country) = line.strip_prefix("loc=") {
                let country = country.trim().to_uppercase();
                if country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic()) {
                    return Ok(country);
                }
            }
        }

        Err("Country not found in Cloudflare response".into())
    }

    async fn get_country_from_ipinfo(&self) -> Result<String, Box<dyn std::error::Error>> {
        // 使用默认客户端
        let client = self.get_default_client().await;
        
        let response = client
            .get("https://ipinfo.io/country")
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let country = response.text().await?;
        let country = country.trim().to_uppercase();

        if country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic()) {
            Ok(country)
        } else {
            Err("Invalid country code from ipinfo.io".into())
        }
    }

    /// Get a reference to the environment.
    pub fn environment(&self) -> &Environment {
        &self.environment
    }

    /// 获取默认客户端（用于兼容旧代码）
    async fn get_default_client(&self) -> Client {
        // 尝试获取代理
        if let Some(proxy_info) = self.proxy_manager.next_proxy() {
            return self.create_client_with_proxy_info(&proxy_info).await;
        }
        
        // 如果没有可用代理，使用默认客户端
        info!("使用默认连接（无代理）");
        ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client")
    }
}

#[async_trait::async_trait]
impl Orchestrator for OrchestratorClient {
    fn environment(&self) -> &Environment {
        &self.environment
    }

    /// Get the user ID associated with a wallet address.
    async fn get_user(&self, wallet_address: &str) -> Result<String, OrchestratorError> {
        let wallet_path = urlencoding::encode(wallet_address).into_owned();
        let endpoint = format!("v3/users/{}", wallet_path);

        // 使用默认节点ID
        let default_node_id = "default";
        let url = self.build_url(&endpoint);
        let user_response: UserResponse = self.execute_get_request(&url, vec![], default_node_id).await?;
        Ok(user_response.user_id)
    }

    /// Registers a new user with the orchestrator.
    async fn register_user(
        &self,
        user_id: &str,
        wallet_address: &str,
    ) -> Result<(), OrchestratorError> {
        let request = RegisterUserRequest {
            uuid: user_id.to_string(),
            wallet_address: wallet_address.to_string(),
        };
        let request_bytes = Self::encode_request(&request);

        // 使用默认节点ID
        let default_node_id = "default";
        let url = self.build_url("v3/users");
        self.execute_post_request_no_response(&url, request_bytes, default_node_id).await
    }

    /// Registers a new node with the orchestrator.
    async fn register_node(&self, user_id: &str) -> Result<String, OrchestratorError> {
        let request = RegisterNodeRequest {
            node_type: NodeType::CliProver as i32,
            user_id: user_id.to_string(),
        };
        let request_bytes = Self::encode_request(&request);

        // 使用默认节点ID
        let default_node_id = "default";
        let url = self.build_url("v3/nodes");
        let response: RegisterNodeResponse = self.execute_post_request(&url, request_bytes, default_node_id).await?;
        Ok(response.node_id)
    }

    async fn get_tasks(&self, node_id: &str) -> Result<Vec<Task>, OrchestratorError> {
        let request = GetTasksRequest {
            node_id: node_id.to_string(),
            next_cursor: "".to_string(),
        };
        let request_bytes = Self::encode_request(&request);

        // 使用带节点ID的请求方法
        let response: GetTasksResponse = self.get_request_with_retry("v3/tasks", request_bytes, node_id).await?;
        let tasks = response.tasks.iter().map(Task::from).collect();
        Ok(tasks)
    }

    async fn get_proof_task(
        &self,
        node_id: &str,
        verifying_key: VerifyingKey,
    ) -> Result<Task, OrchestratorError> {
        let request = GetProofTaskRequest {
            node_id: node_id.to_string(),
            node_type: NodeType::CliProver as i32,
            ed25519_public_key: verifying_key.to_bytes().to_vec(),
        };
        let request_bytes = Self::encode_request(&request);

        // 使用带节点ID的请求方法
        let response: GetProofTaskResponse = self.post_request_with_retry("v3/tasks", request_bytes, node_id).await?;
        Ok(Task::from(&response))
    }

    async fn submit_proof(
        &self,
        task_id: &str,
        proof_hash: &str,
        proof: Vec<u8>,
        signing_key: SigningKey,
        num_provers: usize,
    ) -> Result<(), OrchestratorError> {
        let (program_memory, total_memory) = get_memory_info();
        let flops = estimate_peak_gflops(num_provers);
        let (signature, public_key) = self.create_signature(&signing_key, task_id, proof_hash);

        // Detect country for network optimization (privacy-preserving: only country code, no precise location)
        let location = self.get_country().await;
        let request = SubmitProofRequest {
            task_id: task_id.to_string(),
            node_type: NodeType::CliProver as i32,
            proof_hash: proof_hash.to_string(),
            proof,
            node_telemetry: Some(crate::nexus_orchestrator::NodeTelemetry {
                flops_per_sec: Some(flops as i32),
                memory_used: Some(program_memory),
                memory_capacity: Some(total_memory),
                // Country code for network routing optimization (privacy-preserving)
                location: Some(location),
            }),
            ed25519_public_key: public_key,
            signature,
        };
        let request_bytes = Self::encode_request(&request);

        // 使用带节点ID的请求方法（从task_id提取节点信息）
        // 这里假设task_id可以作为节点的唯一标识
        self.post_request_no_response_with_retry("v3/tasks/submit", request_bytes, task_id).await
    }
}

#[cfg(test)]
/// These are ignored by default since they require a live orchestrator to run.
mod live_orchestrator_tests {
    use crate::environment::Environment;
    use crate::orchestrator::Orchestrator;

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should register a new user with the orchestrator.
    async fn test_register_user() {
        let client = super::OrchestratorClient::new(Environment::Beta);
        // UUIDv4 for the user ID
        let user_id = uuid::Uuid::new_v4().to_string();
        let wallet_address = "0x1234567890abcdef1234567890cbaabc12345678"; // Example wallet address
        match client.register_user(&user_id, wallet_address).await {
            Ok(_) => println!("User registered successfully: {}", user_id),
            Err(e) => panic!("Failed to register user: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should register a new node to an existing user.
    async fn test_register_node() {
        let client = super::OrchestratorClient::new(Environment::Beta);
        let user_id = "78db0be7-f603-4511-9576-c660f3c58395";
        match client.register_node(user_id).await {
            Ok(node_id) => println!("Node registered successfully: {}", node_id),
            Err(e) => panic!("Failed to register node: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should return a new proof task for the node.
    async fn test_get_proof_task() {
        let client = super::OrchestratorClient::new(Environment::Beta);
        let node_id = "5880437"; // Example node ID
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let result = client.get_proof_task(node_id, verifying_key).await;
        match result {
            Ok(task) => {
                println!("Retrieved task: {:?}", task);
            }
            Err(e) => {
                panic!("Failed to get proof task: {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should return the list of existing tasks for the node.
    async fn test_get_tasks() {
        let client = super::OrchestratorClient::new(Environment::Beta);
        let node_id = "5880437"; // Example node ID
        match client.get_tasks(node_id).await {
            Ok(tasks) => {
                println!("Retrieved {} tasks for node {}", tasks.len(), node_id);
                for task in &tasks {
                    println!("Task: {}", task);
                }
            }
            Err(e) => {
                panic!("Failed to get tasks: {}", e);
            }
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should return the user ID associated with a previously-registered wallet address.
    async fn test_get_user() {
        let client = super::OrchestratorClient::new(Environment::Beta);
        let wallet_address = "0x52908400098527886E0F7030069857D2E4169EE8";
        match client.get_user(wallet_address).await {
            Ok(user_id) => {
                println!("User ID for wallet {}: {}", wallet_address, user_id);
                assert_eq!(user_id, "e3c62f51-e566-4f9e-bccb-be9f8cb474be");
            }
            Err(e) => panic!("Failed to get user ID: {}", e),
        }
    }

    #[tokio::test]
    /// Should detect country using Cloudflare/fallback services.
    async fn test_country_detection() {
        let client = super::OrchestratorClient::new(Environment::Beta);
        let country = client.get_country().await;

        println!("Detected country: {}", country);

        // Should be a valid 2-letter country code
        assert_eq!(country.len(), 2);
        assert!(country.chars().all(|c| c.is_ascii_uppercase()));
    }
}
