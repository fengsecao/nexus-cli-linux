// Copyright (c) 2024 Nexus. All rights reserved.

mod analytics;
mod config;
mod consts;
mod environment;
mod error_classifier;
mod events;
mod keys;
mod logging;
mod key_manager;
mod node_list;
mod orchestrator_client_enhanced;  // 确保导入了增强版客户端
#[path = "proto/nexus.orchestrator.rs"]
mod nexus_orchestrator;
mod orchestrator;
mod pretty;
mod prover;
mod prover_runtime;
mod register;
pub mod system;
mod task;
mod task_cache;
mod ui;
mod utils;
mod workers;
mod setup;

use crate::config::{Config, get_config_path};
use crate::environment::Environment;
use crate::orchestrator::OrchestratorClient;
use crate::prover_runtime::{start_anonymous_workers, start_authenticated_workers};
use crate::register::{register_node, register_user};
use crate::utils::system::MemoryDefragmenter;
use clap::{ArgAction, Parser, Subcommand};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{error::Error, io};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use log::warn;
use tokio::sync::broadcast;
use tokio::sync::RwLock;

use std::time::Duration;
// 移除tokio::sync::Mutex的导入，因为我们使用std::sync::Mutex
// use tokio::sync::Mutex;

// 导入全局活跃节点计数函数
use crate::prover_runtime::get_global_active_node_count;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
/// Command-line arguments
struct Args {
    /// Command to execute
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the prover
    Start {
        /// Node ID
        #[arg(long, value_name = "NODE_ID")]
        node_id: Option<u64>,

        /// Run without the terminal UI
        #[arg(long = "headless", action = ArgAction::SetTrue)]
        headless: bool,

        /// Maximum number of threads to use for proving.
        #[arg(long = "max-threads", value_name = "MAX_THREADS")]
        max_threads: Option<u32>,
        
        /// Path to proxy list file
        #[arg(long = "proxy-file", value_name = "PROXY_FILE")]
        proxy_file: Option<String>,
        
        /// Timeout in seconds for 429 errors (will vary by ±10%)
        #[arg(long = "timeout", value_name = "TIMEOUT")]
        timeout: Option<u64>,
    },
    /// Register a new user
    RegisterUser {
        /// User's public Ethereum wallet address. 42-character hex string starting with '0x'
        #[arg(long, value_name = "WALLET_ADDRESS")]
        wallet_address: String,
    },
    /// Register a new node to an existing user, or link an existing node to a user.
    RegisterNode {
        /// ID of the node to register. If not provided, a new node will be created.
        #[arg(long, value_name = "NODE_ID")]
        node_id: Option<u64>,
    },
    /// Clear the node configuration and logout.
    Logout,
    /// Start multiple provers from node list file (optimized version)
    BatchFile {
        /// Path to node list file (.txt)
        #[arg(long, value_name = "FILE_PATH")]
        file: String,

        /// Environment to connect to.
        #[arg(long)]
        env: Option<String>,

        /// Delay between starting each node (seconds)
        #[arg(long, default_value = "3")]
        start_delay: f64,

        /// Delay between proof submissions per node (seconds)
        #[arg(long, default_value = "1")]
        proof_interval: u64,

        /// Maximum number of concurrent nodes
        #[arg(long, default_value = "10")]
        max_concurrent: usize,
        
        /// Number of worker threads per node
        #[arg(long, default_value = "1")]
        workers_per_node: usize,

        /// Enable verbose error logging
        #[arg(long)]
        verbose: bool,
        
        /// Path to proxy list file
        #[arg(long = "proxy-file", value_name = "PROXY_FILE")]
        proxy_file: Option<String>,
        
        /// Timeout in seconds for 429 errors (will vary by ±10%)
        #[arg(long = "timeout", value_name = "TIMEOUT")]
        timeout: Option<u64>,
        
        /// Enable node rotation (switch to next node after success or consecutive 429 error)
        #[arg(long, action = ArgAction::SetTrue)]
        rotation: bool,

        /// Display refresh interval in seconds (0 for immediate updates)
        #[arg(long, default_value = "1")]
        refresh_interval: u64,

        /// Initial request rate per second
        #[arg(long = "initial-rate")]
        initial_rate: Option<f64>,

        /// Minimum request rate per second
        #[arg(long = "min-rate")]
        min_rate: Option<f64>,

        /// Maximum request rate per second
        #[arg(long = "max-rate")]
        max_rate: Option<f64>,
    },
}

/// Fixed line display manager for batch processing with advanced memory optimization
#[derive(Debug)]
struct FixedLineDisplay {
    node_lines: Arc<RwLock<HashMap<u64, String>>>,
    defragmenter: Arc<MemoryDefragmenter>,
    // 持久化的成功和失败计数
    success_count: Arc<AtomicU64>,
    failure_count: Arc<AtomicU64>,
    // 记录启动时间
    start_time: std::time::Instant,
    // 刷新控制
    refresh_interval: Duration,
    last_refresh: Arc<std::sync::Mutex<std::time::Instant>>,
    // 用户设置的最大并发数（显示用）
    max_concurrency: usize,
    // 近5分钟成功时间戳滑窗
    recent_successes: Arc<std::sync::Mutex<std::collections::VecDeque<std::time::Instant>>>,
    // 节点标签（邮箱/evm）
    labels: Arc<std::collections::HashMap<u64, String>>,
    // 最近错误消息（最多5条）
    recent_errors: Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    // 节点在节点列表文件中的行号（1-based）
    line_numbers: Arc<std::collections::HashMap<u64, usize>>,
}

impl FixedLineDisplay {
    fn new(refresh_interval_secs: u64, max_concurrency: usize, labels: Arc<std::collections::HashMap<u64, String>>, line_numbers: Arc<std::collections::HashMap<u64, usize>>) -> Self {
        Self {
            node_lines: Arc::new(RwLock::new(HashMap::new())),
            defragmenter: crate::prover::get_defragmenter(),
            success_count: Arc::new(AtomicU64::new(0)),
            failure_count: Arc::new(AtomicU64::new(0)),
            start_time: std::time::Instant::now(),
            refresh_interval: Duration::from_secs(refresh_interval_secs),
            // 设置为过去的时间，确保首次更新时会立即刷新
            last_refresh: Arc::new(std::sync::Mutex::new(std::time::Instant::now() - Duration::from_secs(60))),
            max_concurrency,
            recent_successes: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            labels,
            recent_errors: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            line_numbers,
        }
    }

    async fn update_node_status(&self, node_id: u64, status: String) {
        // 更新节点状态
        {
            let mut lines = self.node_lines.write().await;
            lines.insert(node_id, status);
        }
        
        // 检查是否应该刷新显示
        let should_refresh = {
            // 如果刷新间隔为0，则始终刷新
            if self.refresh_interval.as_secs() == 0 {
                true
            } else {
                let mut last_refresh = self.last_refresh.lock().unwrap();
                let now = std::time::Instant::now();
                let elapsed = now.duration_since(*last_refresh);
                
                if elapsed >= self.refresh_interval {
                    *last_refresh = now;
                    true
                } else {
                    false
                }
            }
        };
        
        if should_refresh {
            self.render_display().await;
        }
    }

    // 记录一次成功并维护5分钟滑窗
    fn record_success(&self) {
        let mut dq = self.recent_successes.lock().unwrap();
        let now = std::time::Instant::now();
        dq.push_back(now);
        let cutoff = now - Duration::from_secs(5 * 60);
        while let Some(&front) = dq.front() {
            if front < cutoff { dq.pop_front(); } else { break; }
        }
    }

    // 计算近5分钟平均每分钟效率
    fn recent_efficiency_per_min(&self) -> f64 {
        let dq = self.recent_successes.lock().unwrap();
        if dq.is_empty() { return 0.0; }
        let now = std::time::Instant::now();
        let first = dq.front().copied().unwrap_or(now);
        let window_secs = now.saturating_duration_since(first).as_secs_f64().min(5.0 * 60.0).max(1.0);
        (dq.len() as f64) / (window_secs / 60.0)
    }

    // 记录错误消息（最多保留5条）
    fn record_error(&self, msg: String) {
        let mut dq = self.recent_errors.lock().unwrap();
        dq.push_back(msg);
        while dq.len() > 5 { dq.pop_front(); }
    }

    async fn render_display(&self) {
        // 渲染当前状态
        print!("\x1b[2J\x1b[H"); // 清屏并移动到顶部
        
        // 使用缓存的字符串格式
        let mut time_str = self.defragmenter.get_cached_string(64).await;
        time_str.push_str(&chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
        
        println!("🚀 Nexus 增强型批处理挖矿监视器 - {}", time_str);
        println!("═══════════════════════════════════════════");
        
        let lines = self.node_lines.read().await;
        
        // 获取持久化的成功和失败计数
        let (successful_count, failed_count) = self.get_persistent_counts().await;
        
        // 统计信息 - 获取全局活跃节点数量
        let global_active_count = get_global_active_node_count();
        
        // 本地统计信息 - 只计算总节点数量，活跃数使用全局计数
        let total_nodes = lines.len();
        
        println!("📊 状态: {} 总数 | {} 活跃/{} 并发 | {} 成功 | {} 失败", 
                 total_nodes, global_active_count, self.max_concurrency, successful_count, failed_count);
        println!("⏱️ 运行时间: {}天 {}小时 {}分钟 {}秒", 
                 self.start_time.elapsed().as_secs() / 86400,
                 (self.start_time.elapsed().as_secs() % 86400) / 3600,
                 (self.start_time.elapsed().as_secs() % 3600) / 60,
                 self.start_time.elapsed().as_secs() % 60);
        // 效率：每分钟成功次数
        let elapsed_minutes = (self.start_time.elapsed().as_secs_f64() / 60.0).max(0.0001);
        let efficiency_per_min = (successful_count as f64) / elapsed_minutes;
        // 近5分钟滑窗效率
        let recent_eff = self.recent_efficiency_per_min();
        println!("⚡ 效率: {:.2} 次/分钟 | 近5分钟: {:.2} 次/分钟", efficiency_per_min, recent_eff);
        
        // 显示内存统计（包含RAM+SWAP）
        let stats = self.defragmenter.get_stats().await;
        let (used_total_mb, total_mb) = crate::system::get_system_memory_with_swap_mb();
        let memory_percentage = if total_mb > 0 { (used_total_mb as f64 / total_mb as f64) * 100.0 } else { 0.0 };
        // 另外显示单独RAM与SWAP（可选更详细诊断）
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        let ram_used_mb = (sys.used_memory() as f64 / 1_048_576.0).round() as i32;
        let ram_total_mb = (sys.total_memory() as f64 / 1_048_576.0).round() as i32;
        let swap_used_mb = (sys.used_swap() as f64 / 1_048_576.0).round() as i32;
        let swap_total_mb = (sys.total_swap() as f64 / 1_048_576.0).round() as i32;

        // 转为GB并保留1位小数
        let used_total_gb = (used_total_mb as f64) / 1024.0;
        let total_gb = (total_mb as f64) / 1024.0;
        let ram_used_gb = (ram_used_mb as f64) / 1024.0;
        let ram_total_gb = (ram_total_mb as f64) / 1024.0;
        let swap_used_gb = (swap_used_mb as f64) / 1024.0;
        let swap_total_gb = (swap_total_mb as f64) / 1024.0;
        let bytes_freed_gb = (stats.bytes_freed as f64) / 1024.0 / 1024.0 / 1024.0;
 
        println!("🧠 内存(含交换): {:.1}% ({:.1} GB / {:.1} GB)", 
                 memory_percentage, used_total_gb, total_gb);
        println!("   RAM: {:.1}/{:.1} GB | SWAP: {:.1}/{:.1} GB | 清理: {} 次 | 释放: {:.1} GB",
                 ram_used_gb, ram_total_gb,
                 swap_used_gb, swap_total_gb,
                 stats.cleanups_performed,
                 bytes_freed_gb);
        
        println!("───────────────────────────────────────────");
        // 获取全局活跃节点列表并显示最多30行（带标签）
        let active_node_ids = {
            let nodes = crate::prover_runtime::GLOBAL_ACTIVE_NODES.lock();
            nodes.clone()
        };
        if active_node_ids.is_empty() {
            println!("⚠️ 警告: 没有检测到活跃节点，请检查节点状态");
        } else {
            let mut active_sorted: Vec<u64> = active_node_ids.iter().copied().collect();
            active_sorted.sort_unstable();
            for node_id in active_sorted.iter().take(30) {
                let status = lines.get(node_id).cloned().unwrap_or_else(|| {
                    let s = crate::prover_runtime::get_node_state(*node_id);
                    format!("{}", s)
                });
                let line_no_opt = self.line_numbers.get(node_id).copied();
                if let Some(label) = self.labels.get(node_id) {
                    if let Some(line_no) = line_no_opt {
                        println!("节点-{}({}) [{}]: {}", node_id, line_no, label, status);
                    } else {
                        println!("节点-{} [{}]: {}", node_id, label, status);
                    }
                } else {
                    if let Some(line_no) = line_no_opt {
                        println!("节点-{}({}): {}", node_id, line_no, status);
                    } else {
                        println!("节点-{}: {}", node_id, status);
                    }
                }
            }
            let total_active = active_sorted.len();
            if total_active > 30 {
                println!("... 以及 {} 个其他节点 (总共 {} 个活跃节点)", total_active - 30, total_active);
            }
        }
        println!("───────────────────────────────────────────");
        // 最近错误（最多5条）
        {
            let errs = self.recent_errors.lock().unwrap();
            if !errs.is_empty() {
                println!("最近错误:");
                for msg in errs.iter().rev().take(5) {
                    println!("❌ {}", msg);
                }
                println!("───────────────────────────────────────────");
            }
        }
        // 获取当前请求速率
        let (current_rate, _) = crate::prover_runtime::get_global_request_stats();
        println!("刷新间隔: {}秒 | 请求速率: {:.1}次/秒 | 按Ctrl+C退出", 
                 self.refresh_interval.as_secs(), current_rate);
        
        // 归还缓存字符串
        self.defragmenter.return_string(time_str).await;
        
        // 强制刷新输出
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }

    // 获取持久化的成功和失败计数
    async fn get_persistent_counts(&self) -> (u64, u64) {
        let success = self.success_count.load(Ordering::Relaxed);
        let failure = self.failure_count.load(Ordering::Relaxed);
        (success, failure)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let nexus_environment_str = std::env::var("NEXUS_ENVIRONMENT").unwrap_or_default();
    let environment = if nexus_environment_str.is_empty() {
        Environment::default()
    } else {
        match nexus_environment_str.parse::<Environment>() {
            Ok(env) => env,
            Err(_) => {
                eprintln!("Invalid environment: {}", nexus_environment_str);
                return Err("Invalid environment".into());
            }
        }
    };

    let config_path = get_config_path()?;

    let args = Args::parse();
    match args.command {
        Command::Start {
            node_id,
            headless,
            max_threads,
            proxy_file,
            timeout,
        } => {
            let config_path = get_config_path()?;
            return start(node_id, environment, config_path, headless, max_threads, proxy_file, timeout).await;
        }
        Command::Logout => {
            println!("Logging out and clearing node configuration file...");
            Config::clear_node_config(&config_path).map_err(Into::into)
        }
        Command::RegisterUser { wallet_address } => {
            println!("Registering user with wallet address: {}", wallet_address);
            let orchestrator = Box::new(OrchestratorClient::new(environment));
            register_user(&wallet_address, &config_path, orchestrator).await
        }
        Command::RegisterNode { node_id } => {
            let orchestrator = Box::new(OrchestratorClient::new(environment));
            register_node(node_id, &config_path, orchestrator).await
        }
        Command::BatchFile {
            file,
            env,
            start_delay,
            proof_interval,
            max_concurrent,
            workers_per_node,
            verbose,
            proxy_file,
            timeout,
            rotation,
            refresh_interval,
            initial_rate,
            min_rate,
            max_rate,
        } => {
            if verbose {
                // 设置详细日志级别
                unsafe {
                std::env::set_var("RUST_LOG", "debug");
                }
                env_logger::init();
            } else {
                // 设置默认日志级别
                unsafe {
                    std::env::set_var("RUST_LOG", "info");
                }
                env_logger::init();
            }

            // 解析环境变量
            let environment = match env {
                Some(env_str) => {
                    // 尝试将字符串解析为环境类型
                    match env_str.parse::<Environment>() {
                        Ok(env) => env,
                        Err(_) => {
                            eprintln!("Invalid environment: {}", env_str);
                            return Err("Invalid environment".into());
                        }
                    }
                }
                None => Environment::default(),
            };

            // 添加随机变化到启动延迟，在3-5秒之间
            let mut rng = rand::thread_rng();
            let randomized_delay = if start_delay < 3.0 {
                3.0 + rand::Rng::gen_range(&mut rng, 0.0..2.0)
            } else {
                start_delay
            };
            
            start_batch_processing(
                &file,
                environment,
                randomized_delay,
                proof_interval,
                max_concurrent,
                workers_per_node,
                verbose,
                proxy_file,
                timeout,
                rotation,
                refresh_interval,
                initial_rate,
                min_rate,
                max_rate,
            )
            .await
        }
    }
}

/// Starts the Nexus CLI application.
///
/// # Arguments
/// * `node_id` - This client's unique identifier, if available.
/// * `env` - The environment to connect to.
/// * `config_path` - Path to the configuration file.
/// * `headless` - If true, runs without the terminal UI.
/// * `max_threads` - Optional maximum number of threads to use for proving.
/// * `proxy_file` - Path to the proxy list file.
/// * `timeout` - Timeout in seconds for 429 errors (will vary by ±10%).
async fn start(
    node_id: Option<u64>,
    env: Environment,
    config_path: std::path::PathBuf,
    headless: bool,
    max_threads: Option<u32>,
    proxy_file: Option<String>,
    timeout: Option<u64>,
) -> Result<(), Box<dyn Error>> {
    let mut node_id = node_id;
    let _config = match Config::load_from_file(&config_path) {
        Ok(config) => config,
        Err(_) => Config::new(
            String::new(),
            String::new(),
            String::new(),
            Environment::default(),
        ),
    };

    // 设置429超时参数
    if let Some(timeout_value) = timeout {
        // 设置全局429超时参数
        crate::consts::set_retry_timeout(timeout_value);
    }

    // 创建增强型协调器客户端，传入代理文件
    let _orchestrator = crate::orchestrator_client_enhanced::EnhancedOrchestratorClient::new_with_proxy(env.clone(), proxy_file.as_deref());
    // If no node ID is provided, try to load it from the config file.
    if node_id.is_none() && config_path.exists() {
        let config = Config::load_from_file(&config_path)?;
        node_id = Some(config.node_id.parse::<u64>().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Failed to parse node_id {:?} from the config file as a u64: {}",
                    config.node_id, e
                ),
            )
        })?);
        println!("Read Node ID: {} from config file", node_id.unwrap());
    }

    let node_id_value = node_id.unwrap_or_default();
    // 定义状态回调
    let status_callback: Option<Box<dyn Fn(u64, String) + Send + Sync>> = None;

    // Create a signing key for the prover.
    let signing_key = match crate::key_manager::load_or_generate_signing_key() {
        Ok(key) => key,
        Err(e) => {
            warn!("节点 {} 加载签名密钥失败: {}", node_id_value, e);
            if let Some(ref callback) = status_callback {
                callback(node_id_value, format!("加载密钥失败: {}", e));
            }
            return Ok(());
        }
    };
    let orchestrator_client = OrchestratorClient::new(env.clone());
    // Clamp the number of workers to [1,8]. Keep this low for now to avoid rate limiting.
    let num_workers: usize = max_threads.unwrap_or(1).clamp(1, 8) as usize;
    let (shutdown_sender, _) = broadcast::channel(1); // Only one shutdown signal needed

    // Load config to get client_id for analytics
    let config_path = get_config_path()?;
    let client_id = if config_path.exists() {
        match Config::load_from_file(&config_path) {
            Ok(config) => {
                // First try user_id, then node_id, then fallback to UUID
                if !config.user_id.is_empty() {
                    config.user_id
                } else if !config.node_id.is_empty() {
                    config.node_id
                } else {
                    uuid::Uuid::new_v4().to_string() // Fallback to random UUID
                }
            }
            Err(_) => uuid::Uuid::new_v4().to_string(), // Fallback to random UUID
        }
    } else {
        uuid::Uuid::new_v4().to_string() // Fallback to random UUID
    };

    let (mut event_receiver, mut join_handles) = match node_id {
        Some(node_id) => {
            start_authenticated_workers(
                node_id,
                signing_key.clone(),
                orchestrator_client.clone(),
                num_workers,
                shutdown_sender.subscribe(),
                env.clone(),
                client_id,
            )
            .await
        }
        None => {
            start_anonymous_workers(num_workers, shutdown_sender.subscribe(), env.clone(), client_id).await
        }
    };

    if !headless {
        // Terminal setup
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

        // Initialize the terminal with Crossterm backend.
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Create the application and run it.
        let app = ui::App::new(
            node_id,
            orchestrator_client.environment().clone(),
            event_receiver,
            shutdown_sender,
        );
        let res = ui::run(&mut terminal, app).await;

        // Clean up the terminal after running the application.
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        res?;
    } else {
        // Headless mode: log events to console.

        // Trigger shutdown on Ctrl+C
        let shutdown_sender_clone = shutdown_sender.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = shutdown_sender_clone.send(());
            }
        });

        let mut shutdown_receiver = shutdown_sender.subscribe();
        loop {
            tokio::select! {
                Some(event) = event_receiver.recv() => {
                    println!("{}", event);
                }
                _ = shutdown_receiver.recv() => {
                    break;
                }
            }
        }
    }
    println!("\nExiting...");
    for handle in join_handles.drain(..) {
        let _ = handle.await;
    }
    println!("Nexus CLI application exited successfully.");
    Ok(())
}

// 添加批处理函数实现
async fn start_batch_processing(
    file_path: &str,
    environment: Environment,
    start_delay: f64,
    proof_interval: u64,
    max_concurrent: usize,
    workers_per_node: usize,
    verbose: bool,
    proxy_file: Option<String>,
    timeout: Option<u64>,
    rotation: bool,
    refresh_interval: u64,
    initial_rate: Option<f64>,
    min_rate: Option<f64>,
    max_rate: Option<f64>,
) -> Result<(), Box<dyn Error>> {
    // 设置日志输出详细程度
    crate::prover_runtime::set_verbose_output(verbose);
    
    // 禁止所有日志输出，只显示我们的简洁界面
    crate::prover_runtime::set_disable_all_logs(true);
    
    // 设置429超时参数
    if let Some(timeout_value) = timeout {
        // 设置全局429超时参数
        crate::consts::set_retry_timeout(timeout_value);
    }
    
    // 加载节点列表
    let node_ids = node_list::load_node_list(file_path)?;
    if node_ids.is_empty() {
        return Err("节点列表为空".into());
    }
    
    println!("📋 已加载 {} 个节点", node_ids.len());
    
    // 创建增强型协调器客户端，传入代理文件
    let orchestrator = crate::orchestrator_client_enhanced::EnhancedOrchestratorClient::new_with_proxy(environment.clone(), proxy_file.as_deref());
    
    // 计算实际并发数
    let actual_concurrent = max_concurrent.min(node_ids.len());
    
    println!("🚀 Nexus 增强型批处理模式");
    println!("📁 节点文件: {}", file_path);
    println!("📊 节点总数: {}", node_ids.len());
    println!("🔄 最大并发: {}", actual_concurrent);
    println!("⏱️  启动延迟: {:.1}s, 证明间隔: {}s", start_delay, proof_interval);
    if let Some(timeout_val) = timeout {
        println!("⏰ 429错误超时: {}s (±10%)", timeout_val);
    } else {
        println!("⏰ 429错误超时: 默认值");
    }
    println!("🌍 环境: {:?}", environment);
    println!("🧵 每节点工作线程: {}", workers_per_node);
    println!("🧠 内存优化: 已启用");
    println!("📝 详细日志: {}", if verbose { "已启用" } else { "已禁用" });
    println!("🔄 显示刷新间隔: {}秒", refresh_interval);
    if rotation {
        println!("🔄 节点轮转: 已启用 (成功提交或连续1次429错误后立即轮转)");
    } else {
        println!("🔄 节点轮转: 已禁用 (添加 --rotation 参数可启用此功能)");
    }
    
    // 打印请求速率参数
    if let Some(rate) = initial_rate {
        println!("🚦 初始请求速率: 每秒 {} 个请求", rate);
    } else {
        println!("🚦 初始请求速率: 默认值 (每秒1个请求)");
    }
    
    if let Some(rate) = min_rate {
        println!("🚦 最低请求速率: 每秒 {} 个请求", rate);
    } else {
        println!("🚦 最低请求速率: 默认值 (每2秒1个请求)");
    }
    
    if let Some(rate) = max_rate {
        println!("🚦 最高请求速率: 每秒 {} 个请求", rate);
    } else {
        println!("🚦 最高请求速率: 默认值 (每秒10个请求)");
    }
    
    println!("───────────────────────────────────────");
    
    // 创建固定行显示管理器
    let labels_file = if let Some(path) = file_path.rsplit_once('.') {
        Some(path.0.to_string() + ".labels")
    } else {
        None
    };

    let labels_map: Arc<std::collections::HashMap<u64, String>> = Arc::new(
        if let Some(path) = labels_file {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    let mut map = std::collections::HashMap::new();
                    for (lineno, line) in content.lines().enumerate() {
                        let s = line.trim();
                        if s.is_empty() || s.starts_with('#') { continue; }
                        // 支持三种分隔: 逗号/空白/制表
                        let parts: Vec<&str> = s.split(|c: char| c == ',' || c.is_whitespace()).filter(|t| !t.is_empty()).collect();
                        if parts.len() >= 2 {
                            if let Ok(id) = parts[0].parse::<u64>() {
                                map.insert(id, parts[1].to_string());
                            }
                        } else {
                            // 行内只有node_id则忽略，保持兼容
                            let _ = lineno; // no-op
                        }
                    }
                    map
                }
                Err(_) => std::collections::HashMap::new(),
            }
        } else {
            std::collections::HashMap::new()
        }
    );

    // 读取节点列表文件，构建 node_id -> 行号(1-based) 映射
    let line_numbers_map: Arc<std::collections::HashMap<u64, usize>> = Arc::new({
        let mut map = std::collections::HashMap::new();
        if let Ok(content) = std::fs::read_to_string(file_path) {
            let mut entry_index: usize = 0; // 仅对有效节点条目计数（1-based）
            for line in content.lines() {
                let s = line.trim();
                if s.is_empty() || s.starts_with('#') { continue; }
                if let Ok(id) = s.parse::<u64>() {
                    entry_index += 1;
                    map.insert(id, entry_index);
                }
            }
        }
        map
    });
 
    let display = Arc::new(FixedLineDisplay::new(refresh_interval, max_concurrent, labels_map.clone(), line_numbers_map.clone()));
    display.render_display().await;

    // 周期性刷新显示（即使没有状态事件也会刷新）
    {
        let display_clone = display.clone();
        let interval_secs = std::cmp::max(1, refresh_interval) as u64;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                display_clone.render_display().await;
            }
        });
    }
    
    // 创建批处理工作器
    let (shutdown_sender, _) = broadcast::channel(1);
    
    // 使用所有节点，而不仅仅是前actual_concurrent个
    // let current_batch: Vec<_> = node_ids.into_iter().take(actual_concurrent).collect();
    let all_nodes = node_ids; // 使用所有加载的节点
    
    // 创建状态回调
    let display_clone = display.clone();
    let status_callback: Box<dyn Fn(u64, String) + Send + Sync> = Box::new(move |node_id: u64, status: String| {
        let display = display_clone.clone();
        tokio::spawn(async move {
            display.update_node_status(node_id, status).await;
        });
    });
    
    // 启动优化的批处理工作器
    let (mut event_receiver, join_handles) = crate::prover_runtime::start_optimized_batch_workers(
        all_nodes, // 传递所有节点，而不是current_batch
        orchestrator.client.clone(),
        workers_per_node,
        start_delay,
        proof_interval,
        environment.clone(),
        shutdown_sender.subscribe(),
        Some(status_callback),
        proxy_file,
        rotation,
        max_concurrent, // 添加max_concurrent参数
        initial_rate,
        min_rate,
        max_rate,
    ).await;
    
    // 创建消费事件的任务
    let display_clone = display.clone();
    tokio::spawn(async move {
        while let Some(event) = event_receiver.recv().await {
            // 更新成功/失败计数
            if event.event_type == crate::events::EventType::ProofSubmitted {
                let _ = display_clone.success_count.fetch_add(1, Ordering::Relaxed);
                // 记录近5分钟成功时间戳
                display_clone.record_success();
            } else if event.event_type == crate::events::EventType::Error &&
                      (event.msg.contains("Error submitting proof") || 
                       event.msg.contains("Failed to submit proof")) {
                let _ = display_clone.failure_count.fetch_add(1, Ordering::Relaxed);
            }
            // 记录错误信息（任意 Error 事件）
            if event.event_type == crate::events::EventType::Error {
                display_clone.record_error(format!("[{}] {}", event.timestamp, event.msg));
            }
            
            // 只在调试模式下输出事件信息
            #[cfg(debug_assertions)]
            println!("📣 收到事件: 类型={:?}, 消息={}", event.event_type, event.msg);
        }
    });
    
    // 等待 Ctrl+C 信号
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\n接收到 Ctrl+C，正在停止所有节点...");
            let _ = shutdown_sender.send(());
        }
    }
    
    // 等待所有工作器退出
    for handle in join_handles {
        let _ = handle.await;
    }
    
    println!("所有节点已停止");
    Ok(())
}
