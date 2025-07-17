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
use std::collections::HashSet;
use std::time::Duration;
use crate::events::Event; // 修改为从events模块直接导入Event

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
        
        /// 启用详细日志输出（默认为静默模式，只显示关键信息）
        #[arg(long, short, action = ArgAction::SetTrue)]
        verbose_log: bool,
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
}

impl FixedLineDisplay {
    fn new() -> Self {
        Self {
            node_lines: Arc::new(RwLock::new(HashMap::new())),
            defragmenter: crate::prover::get_defragmenter(),
            success_count: Arc::new(AtomicU64::new(0)),
            failure_count: Arc::new(AtomicU64::new(0)),
            start_time: std::time::Instant::now(),
        }
    }

    async fn update_node_status(&self, node_id: u64, status: String) {
        // 移除此处的成功/失败计数逻辑，避免重复计数
        // 计数由事件监听器统一处理
        
        let needs_update = {
            let lines = self.node_lines.read().await;
            // 对于429错误，始终更新显示
            if status.contains("速率限制") || status.contains("429") {
                true
            } else {
            lines.get(&node_id) != Some(&status)
            }
        };
        
        if needs_update {
            {
                let mut lines = self.node_lines.write().await;
                lines.insert(node_id, status);
            }
            self.render_display().await;
        }
    }

    async fn render_display(&self) {
        // 检查内存碎片整理
        if self.defragmenter.should_defragment().await {
            println!("🧹 执行内存碎片整理...");
            let result = self.defragmenter.defragment().await;
            
            if result.was_critical {
                println!("🚨 关键内存清理完成:");
            } else {
                println!("🔧 常规内存清理完成:");
            }
            println!("   内存: {:.1}% → {:.1}% (释放 {:.1}%)", 
                     result.memory_before * 100.0, 
                     result.memory_after * 100.0,
                     result.memory_freed_percentage());
            println!("   释放空间: {} KB", result.bytes_freed / 1024);
        }

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
        
        println!("📊 状态: {} 总数 | {} 活跃 | {} 成功 | {} 失败", 
                 total_nodes, global_active_count, successful_count, failed_count);
        println!("⏱️ 运行时间: {}天 {}小时 {}分钟 {}秒", 
                 self.start_time.elapsed().as_secs() / 86400,
                 (self.start_time.elapsed().as_secs() % 86400) / 3600,
                 (self.start_time.elapsed().as_secs() % 3600) / 60,
                 self.start_time.elapsed().as_secs() % 60);
        
        // 显示内存统计
        let stats = self.defragmenter.get_stats().await;
        let memory_info = crate::system::get_memory_info();
        let memory_percentage = (memory_info.0 as f64 / memory_info.1 as f64) * 100.0;
        
        println!("🧠 内存: {:.1}% ({} MB / {} MB) | 清理次数: {} | 释放: {} KB", 
                memory_percentage, 
               memory_info.0 / 1024 / 1024,  
               memory_info.1 / 1024 / 1024,
                stats.cleanups_performed,
                stats.bytes_freed / 1024);
        
        println!("───────────────────────────────────────────");
        
        // 获取全局活跃节点列表
        let active_node_ids = {
            let nodes = crate::prover_runtime::GLOBAL_ACTIVE_NODES.lock();
            nodes.clone()
        };
        
        // 修改显示逻辑：确保显示所有全局活跃节点，不仅仅是有状态更新的节点
        if active_node_ids.is_empty() {
            println!("⚠️ 警告: 没有检测到活跃节点，请检查节点状态");
        } else {
            // 首先显示已有状态信息的活跃节点
            let mut sorted_lines: Vec<_> = lines.iter()
                .filter(|(id, _)| active_node_ids.contains(id))
                .collect();
            sorted_lines.sort_unstable_by_key(|(id, _)| *id);
            
            for (node_id, status) in &sorted_lines {
                println!("节点-{}: {}", node_id, status);
            }
            
            // 然后显示没有状态信息的活跃节点
            let nodes_with_status: HashSet<u64> = sorted_lines.iter().map(|(id, _)| **id).collect();
            let mut missing_nodes: Vec<u64> = active_node_ids.iter()
                .filter(|id| !nodes_with_status.contains(id))
                .copied()
                .collect();
            missing_nodes.sort_unstable();
            
            for node_id in missing_nodes {
                println!("节点-{}: 已添加到活跃列表，等待状态更新...", node_id);
            }
        }
        
        println!("───────────────────────────────────────────");
        
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
            verbose: _, // 忽略这个未使用的变量
            proxy_file,
            timeout,
            rotation,
            verbose_log,
        } => {
            if verbose_log {
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
                proxy_file,
                timeout,
                rotation,
                verbose_log,
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
    proxy_file: Option<String>,
    timeout: Option<u64>,
    rotation: bool,
    verbose_log: bool,
) -> Result<(), Box<dyn Error>> {
    // 设置429超时参数
    if let Some(timeout_value) = timeout {
        // 设置全局429超时参数
        crate::consts::set_retry_timeout(timeout_value);
    }

    // 读取节点列表文件
    let file_content = std::fs::read_to_string(file_path)?;
    let lines: Vec<&str> = file_content.lines().collect();
    
    // 解析节点ID
    let mut nodes = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        match line.parse::<u64>() {
            Ok(node_id) => nodes.push(node_id),
            Err(_) => {
                eprintln!("无法解析节点ID: {}", line);
                // 跳过无效的节点ID
            }
        }
    }
    
    if nodes.is_empty() {
        return Err("节点列表为空".into());
    }
    
    println!("📋 加载了 {} 个节点", nodes.len());
    
    // 创建协调器客户端
    let orchestrator = OrchestratorClient::new(environment.clone());
    
    // 创建关闭信号通道
    let (shutdown_sender, _) = broadcast::channel(1);
    
    // 创建状态回调
    let display = Arc::new(FixedLineDisplay::new());
    let display_clone = display.clone();
    
    let status_callback: Box<dyn Fn(u64, String) + Send + Sync + 'static> = Box::new(move |node_id, status| {
        let display = display_clone.clone();
        let node_id = node_id;
        let status = status;
        
        tokio::spawn(async move {
            display.update_node_status(node_id, status).await;
        });
    });
    
    // 创建渲染任务
    let render_display = display.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            interval.tick().await;
            render_display.render_display().await;
        }
    });
    
    // 启动批处理工作线程
    let (event_receiver, _join_handles) = crate::prover_runtime::start_optimized_batch_workers(
        nodes,
        orchestrator,
        workers_per_node,
        start_delay,
        proof_interval,
        environment,
        shutdown_sender.subscribe(),
        Some(status_callback),
        proxy_file,
        rotation,
        max_concurrent, // 添加max_concurrent参数
        verbose_log,
    ).await;
    
    // 设置Ctrl+C处理
    let shutdown_sender_clone = shutdown_sender.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = shutdown_sender_clone.send(());
        }
    });
    
    // 处理事件
    let mut shutdown_receiver = shutdown_sender.subscribe();
    loop {
        tokio::select! {
            Some(event) = event_receiver.recv() => {
                match &event {
                    Event::Success(node_id, msg) => {
                        // 更新成功计数
                        display.success_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Event::Error(node_id, msg) => {
                        // 更新失败计数
                        display.failure_count.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
            _ = shutdown_receiver.recv() => {
                println!("\n正在关闭...");
                break;
            }
        }
    }
    
    Ok(())
}
