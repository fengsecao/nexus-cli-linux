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
        let path = Path::new(file_path);
        let file = File::open(path)?;
        let reader = io::BufReader::new(file);
        let mut proxies = Vec::new();

        for line in reader.lines() {
            if let Ok(line) = line {
                if line.trim().is_empty() || line.starts_with('#') {
                    continue;
                }

                // 解析格式: host:port:username:password_country-COUNTRY
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 4 {
                    let host = parts[0];
                    let port = parts[1];
                    let username = parts[2];
                    
                    // 处理密码和国家信息
                    let password_parts: Vec<&str> = parts[3].split("_country-").collect();
                    let password = password_parts[0];
                    let country = if password_parts.len() > 1 { password_parts[1] } else { "UNKNOWN" };
                    
                    let url = format!("http://{}:{}", host, port);
                    
                    proxies.push(ProxyInfo {
                        url,
                        username: username.to_string(),
                        password: password.to_string(),
                        country: country.to_string(),
                    });
                }
            }
        }

        // 更新代理列表
        if !proxies.is_empty() {
            let mut proxy_list = self.proxies.lock().unwrap();
            *proxy_list = proxies;
            info!("已加载 {} 个代理", proxy_list.len());
        } else {
            warn!("代理文件为空或格式不正确");
        }

        Ok(())
    }

    /// 获取下一个代理
    pub fn next_proxy(&self) -> Option<ProxyInfo> {
        let proxies = self.proxies.lock().unwrap();
        if proxies.is_empty() {
            return None;
        }

        // 随机选择一个代理
        let mut rng = thread_rng();
        proxies.choose(&mut rng).cloned()
    }
}

#[derive(Debug, Clone)]
pub struct OrchestratorClient {
    #[allow(dead_code)]
    client: Client,
    environment: Environment,
    proxy_manager: Arc<ProxyManager>,
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
        }
    }

    /// Create a new orchestrator client with proxy support
    pub fn new_with_proxy(environment: Environment, proxy_file: Option<&str>) -> Self {
        let proxy_manager = Arc::new(ProxyManager::new());
        
        // 尝试加载指定的代理文件
        if let Some(file_path) = proxy_file {
            match proxy_manager.load_from_file(file_path) {
                Ok(_) => info!("成功加载代理文件: {}", file_path),
                Err(e) => warn!("无法加载代理文件 {}: {}", file_path, e),
            }
        } else {
            // 尝试加载默认代理文件
            if let Err(e) = proxy_manager.load_from_file("proxy.txt") {
                warn!("无法加载默认代理文件: {}", e);
            }
        }
        
        Self {
            client: ClientBuilder::new()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            environment,
            proxy_manager,
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

    /// 创建带有代理的HTTP客户端
    async fn create_client_with_proxy(&self) -> Client {
        // 尝试获取代理
        if let Some(proxy_info) = self.proxy_manager.next_proxy() {
            info!("使用代理: {} ({})", proxy_info.url, proxy_info.country);
            
            // 创建代理
            match Proxy::all(&proxy_info.url) {
                Ok(proxy) => {
                    let proxy_with_auth = proxy.basic_auth(&proxy_info.username, &proxy_info.password);
                    // 创建新的builder实例
                    let builder = ClientBuilder::new()
                        .timeout(Duration::from_secs(10))
                        .proxy(proxy_with_auth);
                    
                    match builder.build() {
                        Ok(client) => return client,
                        Err(e) => {
                            error!("创建代理客户端失败: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("创建代理失败: {}", e);
                }
            }
        }
        
        // 如果获取代理失败，使用默认客户端
        warn!("使用默认连接（无代理）");
        ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client")
    }

    async fn get_request<T: Message + Default>(
        &self,
        endpoint: &str,
        body: Vec<u8>,
    ) -> Result<T, OrchestratorError> {
        let url = self.build_url(endpoint);
        // 使用动态代理客户端
        let client = self.create_client_with_proxy().await;
        
        let response = client
            .get(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        let response = Self::handle_response_status(response).await?;
        let response_bytes = response.bytes().await?;
        Self::decode_response(&response_bytes)
    }

    async fn post_request<T: Message + Default>(
        &self,
        endpoint: &str,
        body: Vec<u8>,
    ) -> Result<T, OrchestratorError> {
        let url = self.build_url(endpoint);
        // 使用动态代理客户端
        let client = self.create_client_with_proxy().await;
        
        let response = client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        let response = Self::handle_response_status(response).await?;
        let response_bytes = response.bytes().await?;
        Self::decode_response(&response_bytes)
    }

    async fn post_request_no_response(
        &self,
        endpoint: &str,
        body: Vec<u8>,
    ) -> Result<(), OrchestratorError> {
        let url = self.build_url(endpoint);
        // 使用动态代理客户端
        let client = self.create_client_with_proxy().await;
        
        let response = client
            .post(&url)
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
        // 使用动态代理客户端
        let client = self.create_client_with_proxy().await;
        
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
        // 使用动态代理客户端
        let client = self.create_client_with_proxy().await;
        
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

        let user_response: UserResponse = self.get_request(&endpoint, vec![]).await?;
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

        self.post_request_no_response("v3/users", request_bytes)
            .await
    }

    /// Registers a new node with the orchestrator.
    async fn register_node(&self, user_id: &str) -> Result<String, OrchestratorError> {
        let request = RegisterNodeRequest {
            node_type: NodeType::CliProver as i32,
            user_id: user_id.to_string(),
        };
        let request_bytes = Self::encode_request(&request);

        let response: RegisterNodeResponse = self.post_request("v3/nodes", request_bytes).await?;
        Ok(response.node_id)
    }

    async fn get_tasks(&self, node_id: &str) -> Result<Vec<Task>, OrchestratorError> {
        let request = GetTasksRequest {
            node_id: node_id.to_string(),
            next_cursor: "".to_string(),
        };
        let request_bytes = Self::encode_request(&request);

        let response: GetTasksResponse = self.get_request("v3/tasks", request_bytes).await?;
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

        let response: GetProofTaskResponse = self.post_request("v3/tasks", request_bytes).await?;
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

        self.post_request_no_response("v3/tasks/submit", request_bytes)
            .await
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
