//! Prover Runtime
//!
//! Main orchestrator for authenticated and anonymous proving modes.
//! Coordinates online workers (network I/O) and offline workers (computation).

use crate::consts::prover::{EVENT_QUEUE_SIZE, RESULT_QUEUE_SIZE, TASK_QUEUE_SIZE};
use crate::environment::Environment;
use crate::events::Event;
use crate::orchestrator::OrchestratorClient;
use crate::task::Task;
use crate::task_cache::TaskCache;
use crate::workers::{offline, online};
use crate::system::{check_memory_pressure, perform_memory_cleanup};
use crate::prover::get_defragmenter;
use ed25519_dalek::SigningKey;
use nexus_sdk::stwo::seq::Proof;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use std::sync::atomic::{AtomicU64, Ordering, AtomicBool};
use std::time::Duration;
use parking_lot::Mutex;
use once_cell::sync::Lazy;
use rand;
use log::{debug, warn};
use crate::orchestrator_client_enhanced::EnhancedOrchestratorClient;
use sha3::Digest;
use postcard;
use std::sync::Arc;
use std::collections::HashMap;

/// Maximum number of completed tasks to keep in memory. Chosen to be larger than the task queue size.
const MAX_COMPLETED_TASKS: usize = 500;

// 高性能时间戳缓存 - 避免重复格式化
static LAST_TIMESTAMP_SEC: AtomicU64 = AtomicU64::new(0);
static CACHED_TIMESTAMP: Lazy<Mutex<String>> = Lazy::new(|| {
    Mutex::new(chrono::Local::now().format("%H:%M:%S").to_string())
});

/// 高性能时间戳生成 - 秒级缓存避免重复格式化
fn get_timestamp_efficient() -> String {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let last = LAST_TIMESTAMP_SEC.load(Ordering::Relaxed);
    
    if now_secs != last && LAST_TIMESTAMP_SEC.compare_exchange_weak(
        last, now_secs, Ordering::Relaxed, Ordering::Relaxed
    ).is_ok() {
        // 仅当秒数变化时重新格式化
        let new_timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
        *CACHED_TIMESTAMP.lock() = new_timestamp.clone();
        new_timestamp
    } else {
        // 使用缓存的时间戳
        CACHED_TIMESTAMP.lock().clone()
    }
}

/// Starts authenticated workers that fetch tasks from the orchestrator and process them.
pub async fn start_authenticated_workers(
    node_id: u64,
    signing_key: SigningKey,
    orchestrator: OrchestratorClient,
    num_workers: usize,
    shutdown: broadcast::Receiver<()>,
    environment: Environment,
    client_id: String,
) -> (mpsc::Receiver<Event>, Vec<JoinHandle<()>>) {
    let mut join_handles = Vec::new();
    // Worker events
    let (event_sender, event_receiver) = mpsc::channel::<Event>(EVENT_QUEUE_SIZE);

    // A bounded list of recently fetched task IDs (prevents refetching currently processing tasks)
    let enqueued_tasks = TaskCache::new(MAX_COMPLETED_TASKS);
    
    // 创建节点速率限制跟踪器
    let rate_limit_tracker = online::NodeRateLimitTracker::new();

    // Task fetching
    let (task_sender, task_receiver) = mpsc::channel::<Task>(TASK_QUEUE_SIZE);
    let verifying_key = signing_key.verifying_key();
    let fetch_prover_tasks_handle = {
        let orchestrator = orchestrator.clone();
        let event_sender = event_sender.clone();
        let shutdown = shutdown.resubscribe(); // Clone the receiver for task fetching
        let rate_limit_tracker_clone = rate_limit_tracker.clone();
        tokio::spawn(async move {
            online::fetch_prover_tasks(
                node_id,
                verifying_key,
                Box::new(orchestrator),
                task_sender,
                event_sender,
                shutdown,
                enqueued_tasks,
                rate_limit_tracker_clone,
            )
            .await;
        })
    };
    join_handles.push(fetch_prover_tasks_handle);

    // Workers
    let (result_sender, result_receiver) = mpsc::channel::<(Task, Proof)>(RESULT_QUEUE_SIZE);

    let (worker_senders, worker_handles) = offline::start_workers(
        num_workers,
        result_sender,
        event_sender.clone(),
        shutdown.resubscribe(),
        environment,
        client_id,
    );
    join_handles.extend(worker_handles);

    // Dispatch tasks to workers
    let dispatcher_handle =
        offline::start_dispatcher(task_receiver, worker_senders, shutdown.resubscribe());
    join_handles.push(dispatcher_handle);

    // A bounded list of recently completed task IDs (prevents duplicate proof submissions)
    let successful_tasks = TaskCache::new(MAX_COMPLETED_TASKS);

    // Send proofs to the orchestrator
    let submit_proofs_handle = online::submit_proofs(
        signing_key,
        Box::new(orchestrator),
        num_workers,
        result_receiver,
        event_sender.clone(),
        shutdown.resubscribe(),
        successful_tasks.clone(),
        rate_limit_tracker,
    )
    .await;
    join_handles.push(submit_proofs_handle);

    (event_receiver, join_handles)
}

/// Starts anonymous workers that repeatedly prove a program with hardcoded inputs.
pub async fn start_anonymous_workers(
    num_workers: usize,
    shutdown: broadcast::Receiver<()>,
    environment: Environment,
    client_id: String,
) -> (mpsc::Receiver<Event>, Vec<JoinHandle<()>>) {
    offline::start_anonymous_workers(num_workers, shutdown, environment, client_id).await
}

/// 内存优化的多节点批处理模式 - 自适应内存管理
pub async fn start_optimized_batch_workers(
    nodes: Vec<u64>,
    _orchestrator: OrchestratorClient,
    num_workers_per_node: usize,
    start_delay: f64,
    proof_interval: u64,
    environment: Environment,
    shutdown: broadcast::Receiver<()>,
    status_callback: Option<Box<dyn Fn(u64, String) + Send + Sync + 'static>>,
    proxy_file: Option<String>,
    rotation: bool,
    max_concurrent: usize, // 添加max_concurrent参数
) -> (mpsc::Receiver<Event>, Vec<JoinHandle<()>>) {
    // Worker事件
    let (event_sender, event_receiver) = mpsc::channel::<Event>(EVENT_QUEUE_SIZE);
    let mut join_handles = Vec::new();
    let defragmenter = get_defragmenter();
    
    // 将回调函数包装在Arc中，这样可以在多个任务之间共享
    let status_callback_arc = status_callback.map(Arc::new);
    
    // 预初始化证明器 - 确保它们被共享
    let _ = crate::prover::get_or_create_default_prover().await;
    let _ = crate::prover::get_or_create_initial_prover().await;
    
    // 增加初始延迟，避免一次性启动太多节点导致429错误
    let initial_delay = 3.0; // 3秒初始延迟
    println!("等待初始延迟 {:.1}秒...", initial_delay);
    tokio::time::sleep(std::time::Duration::from_secs_f64(initial_delay)).await;
    
    // 计算实际并发数（最大并发数与节点数量的较小值）
    let actual_concurrent = max_concurrent.min(nodes.len());
    println!("🧮 设置的并发数: {}, 实际并发数: {}", max_concurrent, actual_concurrent);
    
    // 创建一个跟踪活跃线程的映射
    let active_threads = Arc::new(Mutex::new(HashMap::<u64, bool>::new()));
    
    // 初始化所有节点为未启动状态
    {
        let mut active_threads_guard = active_threads.lock();
        for &node_id in &nodes {
            active_threads_guard.insert(node_id, false);
        }
    }
    
    // 创建一个用于节点管理器和工作线程之间通信的通道
    let (node_tx, node_rx) = mpsc::channel::<NodeManagerCommand>(100);
    
    // 如果启用了轮转功能，创建节点队列和活动节点跟踪器
    let all_nodes = Arc::new(nodes.clone());
    let rotation_data = if rotation {
        println!("🔄 启用节点轮转功能 - 总节点数: {}", nodes.len());
        // 创建一个共享的活动节点队列和下一个可用节点索引
        let active_nodes = Arc::new(Mutex::new(Vec::new()));
        
        // 创建一个标志，表示所有初始节点是否已启动
        let all_nodes_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        
        // 创建一个节点映射表，用于记录每个节点的原始索引
        let node_indices = Arc::new(Mutex::new(HashMap::<u64, usize>::new()));
        
        // 初始化下一个节点索引为实际并发数，这样第一个轮转的节点会从并发数之后开始
        let next_node_index = Arc::new(AtomicU64::new(actual_concurrent as u64));
        
        // 初始化活动节点队列和节点索引映射
        {
            let mut active_nodes_guard = active_nodes.lock();
            let mut node_indices_guard = node_indices.lock();
            
            // 确保使用前actual_concurrent个节点（按照索引顺序）
            let mut sorted_nodes: Vec<(usize, u64)> = nodes.iter().enumerate().map(|(idx, &id)| (idx, id)).collect();
            sorted_nodes.sort_by_key(|(idx, _)| *idx);
            
            // 只添加前actual_concurrent个节点到活动队列
            for (idx, node_id) in sorted_nodes.iter().take(actual_concurrent) {
                active_nodes_guard.push(*node_id);
                node_indices_guard.insert(*node_id, *idx);
                println!("🔄 添加节点-{} 到活动节点队列 (索引: {})", node_id, idx);
                
                // 标记节点为未启动
                let mut active_threads_guard = active_threads.lock();
                active_threads_guard.insert(*node_id, false);
            }
            
            // 初始化剩余节点的索引映射
            for (idx, node_id) in sorted_nodes.iter().skip(actual_concurrent) {
                node_indices_guard.insert(*node_id, *idx);
            }
            
            println!("🔄 初始活动节点队列: {:?}", *active_nodes_guard);
            println!("🔄 下一个节点索引: {}", next_node_index.load(std::sync::atomic::Ordering::SeqCst));
            println!("🔄 最大并发数: {}, 总节点数: {}", actual_concurrent, nodes.len());
        } // 锁在这里释放
        
        Some((active_nodes.clone(), next_node_index.clone(), all_nodes.clone(), all_nodes_started.clone(), node_indices.clone(), actual_concurrent))
    } else {
        println!("⚠️ 节点轮转功能未启用");
        None
    };
    
    // 启动节点管理器
    if rotation {
        if let Some((active_nodes_clone, _next_node_index_clone, _all_nodes_clone, all_nodes_started_clone, _node_indices_clone, _actual_concurrent)) = rotation_data.clone() {
            let active_threads_for_manager = active_threads.clone();
            let environment_for_manager = environment.clone();
            let proxy_file_for_manager = proxy_file.clone();
            let status_callback_for_manager = status_callback_arc.clone();
            let event_sender_for_manager = event_sender.clone();
            let shutdown_for_manager = shutdown.resubscribe();
            let node_rx_for_manager = node_rx;
            let rotation_data_for_manager = rotation_data.clone();
            
            // 打印初始活动节点列表
            {
                let active_nodes_guard = active_nodes_clone.lock();
                println!("🔄 启动节点管理器线程 - 初始活动节点列表: {:?}", *active_nodes_guard);
            }
            
            println!("🔄 启动节点管理器线程");
            let manager_handle = tokio::spawn(async move {
                node_manager(
                    active_nodes_clone,
                    active_threads_for_manager,
                    environment_for_manager,
                    proxy_file_for_manager,
                    num_workers_per_node,
                    proof_interval,
                    status_callback_for_manager,
                    event_sender_for_manager,
                    shutdown_for_manager,
                    node_rx_for_manager,
                    rotation_data_for_manager,
                ).await;
            });
            
            join_handles.push(manager_handle);
            
            // 创建一个任务来监控所有初始节点是否已启动
            let active_threads_monitor = active_threads.clone();
            let all_nodes_started_monitor = all_nodes_started_clone.clone();
            
            tokio::spawn(async move {
                loop {
                    // 检查所有初始节点是否已启动
                    let all_started = {
                        let active_threads_guard = active_threads_monitor.lock();
                        let mut all_started = true;
                        
                        // 检查每个活动节点是否已启动
                        for (_, &started) in active_threads_guard.iter() {
                            if !started {
                                all_started = false;
                                break;
                            }
                        }
                        
                        all_started
                    };
                    
                    if all_started {
                        // 设置所有节点已启动标志
                        all_nodes_started_monitor.store(true, std::sync::atomic::Ordering::SeqCst);
                        println!("🚀 所有初始节点已启动，可以开始轮转");
                        break;
                    }
                    
                    // 等待一段时间后再次检查
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            });
        }
    }
    
    // 创建节点管理器通信通道的克隆，用于节点通信
    let node_tx_for_nodes = node_tx.clone();

    // 获取活动节点列表
    let active_nodes_list = if let Some((active_nodes, _, _, _, _, _)) = &rotation_data {
        let active_nodes_guard = active_nodes.lock();
        active_nodes_guard.clone()
    } else {
        // 如果未启用轮转，则使用前actual_concurrent个节点
        nodes.iter().take(actual_concurrent).copied().collect()
    };
    
    println!("🔄 准备按顺序启动以下节点: {:?}", active_nodes_list);

    // 按序启动各节点
    for (index, node_id) in active_nodes_list.iter().enumerate() {
        // 添加启动延迟
        if index > 0 {
            // 使用更长的延迟，特别是对于前几个节点
            let actual_delay = if index < 5 {
                // 前5个节点使用更长的延迟
                start_delay * 2.0
            } else {
                start_delay
            };
            
            println!("启动节点 {} (第{}/{}个), 延迟 {:.1}秒...", 
                    node_id, index + 1, actual_concurrent, actual_delay);
            tokio::time::sleep(std::time::Duration::from_secs_f64(actual_delay)).await;
        }
        
        // 检查内存压力，如果需要则等待更长时间
        if check_memory_pressure() {
            debug!("节点 {} 启动前检测到内存压力，执行清理...", node_id);
            perform_memory_cleanup();
            
            // 在节点启动前进行内存碎片整理
            if defragmenter.should_defragment().await {
                let result = defragmenter.defragment().await;
                debug!("节点 {} 启动前内存碎片整理: {:.1}% → {:.1}%", 
                      node_id, result.memory_before * 100.0, result.memory_after * 100.0);
            }
            
            // 额外等待让内存清理生效
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        
        let handle = start_node_worker(
            *node_id,
            environment.clone(),
            proxy_file.clone(),
            num_workers_per_node,
            proof_interval,
            status_callback_arc.clone(),
            event_sender.clone(),
            shutdown.resubscribe(),
            rotation_data.clone(),
            active_threads.clone(),
            node_tx_for_nodes.clone(), // 使用克隆的通信通道
        ).await;
        
        join_handles.push(handle);
    }
    
    (event_receiver, join_handles)
}

// 节点管理器命令枚举
#[derive(Debug)]
enum NodeManagerCommand {
    NodeStarted(u64),
    NodeStopped(u64),
}

// 节点管理器函数
async fn node_manager(
    active_nodes: Arc<Mutex<Vec<u64>>>,
    active_threads: Arc<Mutex<HashMap<u64, bool>>>,
    environment: Environment,
    proxy_file: Option<String>,
    num_workers_per_node: usize,
    proof_interval: u64,
    status_callback_arc: Option<Arc<Box<dyn Fn(u64, String) + Send + Sync + 'static>>>,
    event_sender: mpsc::Sender<Event>,
    mut shutdown: broadcast::Receiver<()>,
    mut node_rx: mpsc::Receiver<NodeManagerCommand>,
    rotation_data: Option<(Arc<Mutex<Vec<u64>>>, Arc<AtomicU64>, Arc<Vec<u64>>, Arc<std::sync::atomic::AtomicBool>, Arc<Mutex<HashMap<u64, usize>>>, usize)>,
) {
    println!("🔄 节点管理器启动");
    
    // 获取最大并发数
    let max_concurrent = if let Some((_, _, _, _, _, max_concurrent)) = &rotation_data {
        *max_concurrent
    } else {
        10 // 默认值
    };
    
    println!("🔄 节点管理器: 最大并发数设置为 {}", max_concurrent);
    
    // 添加一个定期检查标志，避免过于频繁的检查
    let mut last_check_time = std::time::Instant::now();
    let check_interval = std::time::Duration::from_secs(1); // 减少检查间隔为1秒
    
    // 创建一个节点启动队列，用于记录需要启动的节点
    let mut nodes_to_start = Vec::new();
    
    // 创建一个全局通信通道，用于节点间通信
    let (global_tx, mut global_rx) = mpsc::channel::<NodeManagerCommand>(100); // 增大缓冲区大小
    
    // 创建一个任务来处理全局通信通道的消息
    let active_threads_clone = active_threads.clone();
    let active_nodes_clone = active_nodes.clone();
    let env_clone = environment.clone();
    let proxy_clone = proxy_file.clone();
    let callback_clone = status_callback_arc.clone();
    let event_sender_clone = event_sender.clone();
    let rotation_clone = rotation_data.clone();
    let global_tx_clone = global_tx.clone(); // 为闭包创建一个克隆
    let shutdown_clone = shutdown.resubscribe(); // 为闭包创建一个克隆
    
    // 启动一个后台任务来处理全局通信通道的消息
    tokio::spawn(async move {
        while let Some(cmd) = global_rx.recv().await {
            match cmd {
                NodeManagerCommand::NodeStopped(node_id) => {
                    println!("🌐 全局通信: 节点-{} 已停止", node_id);
                    // 在单独作用域内更新状态，避免跨await持有锁
                    {
                        let mut active_threads_guard = active_threads_clone.lock();
                        active_threads_guard.insert(node_id, false);
                    }
                    
                    // 立即检查是否有新节点需要启动
                    println!("🌐 全局通信: 节点-{} 已停止，检查是否需要启动新节点", node_id);
                    
                    // 获取需要启动的节点列表
                    let new_nodes = get_nodes_to_start(&active_nodes_clone, &active_threads_clone).await;
                    
                    // 检查当前活动节点数量
                    let current_active_count = {
                        let active_threads_guard = active_threads_clone.lock();
                        active_threads_guard.iter().filter(|(_, &active)| active).count()
                    };
                    
                    // 只有当活动节点数量低于最大并发数时才启动新节点
                    if current_active_count < max_concurrent {
                        // 计算可以启动的节点数量
                        let nodes_to_start_count = (max_concurrent - current_active_count).min(new_nodes.len());
                        
                        if nodes_to_start_count > 0 {
                            println!("🌐 全局通信: 当前活动节点数量: {}, 最大并发数: {}, 将启动 {} 个新节点", 
                                    current_active_count, max_concurrent, nodes_to_start_count);
                            
                            // 只启动需要的节点数量
                            for node_id in new_nodes.iter().take(nodes_to_start_count) {
                                println!("🌐 全局通信: 准备启动节点-{}", node_id);
                                
                                // 使用全局通信通道的克隆
                                let node_tx = global_tx_clone.clone();
                                
                                // 启动新节点
                                let handle = start_node_worker(
                                    *node_id,
                                    env_clone.clone(),
                                    proxy_clone.clone(),
                                    num_workers_per_node,
                                    proof_interval,
                                    callback_clone.clone(),
                                    event_sender_clone.clone(),
                                    shutdown_clone.resubscribe(), // 使用克隆的shutdown
                                    rotation_clone.clone(),
                                    active_threads_clone.clone(),
                                    node_tx,
                                ).await;
                                
                                // 这里不需要存储handle，因为我们只关心节点是否在运行
                                tokio::spawn(async move {
                                    let _ = handle.await;
                                    println!("⚠️ 节点工作线程已完成");
                                });
                                
                                // 添加一个短暂的延迟，避免同时启动太多节点
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        } else {
                            println!("🌐 全局通信: 当前活动节点数量: {}, 最大并发数: {}, 无需启动新节点", 
                                    current_active_count, max_concurrent);
                        }
                    } else {
                        println!("🌐 全局通信: 当前活动节点数量: {} 已达到或超过最大并发数: {}, 不启动新节点", 
                                current_active_count, max_concurrent);
                    }
                },
                NodeManagerCommand::NodeStarted(node_id) => {
                    println!("🌐 全局通信: 节点-{} 已启动", node_id);
                    // 在单独作用域内更新状态，避免跨await持有锁
                    {
                        let mut active_threads_guard = active_threads_clone.lock();
                        active_threads_guard.insert(node_id, true);
                    }
                }
            }
        }
    });
    
    loop {
        // 首先检查是否有需要启动的节点
        if !nodes_to_start.is_empty() {
            // 检查当前活动节点数量
            let current_active_count = {
                let active_threads_guard = active_threads.lock();
                active_threads_guard.iter().filter(|(_, &active)| active).count()
            };
            
            // 只有当活动节点数量低于最大并发数时才启动新节点
            if current_active_count < max_concurrent {
                // 计算可以启动的节点数量
                let nodes_to_start_count = (max_concurrent - current_active_count).min(nodes_to_start.len());
                
                if nodes_to_start_count > 0 {
                    println!("🔄 节点管理器: 当前活动节点数量: {}, 最大并发数: {}, 将启动 {} 个新节点", 
                            current_active_count, max_concurrent, nodes_to_start_count);
                    
                    // 只启动需要的节点数量
                    let nodes_to_launch: Vec<u64> = nodes_to_start.drain(..nodes_to_start_count).collect();
                    
                    for node_id in nodes_to_launch {
                        println!("🔄 节点管理器: 准备启动节点-{}", node_id);
                        
                        // 使用全局通信通道
                        let node_tx = global_tx.clone();
                        
                        // 启动新节点
                        let handle = start_node_worker(
                            node_id,
                            environment.clone(),
                            proxy_file.clone(),
                            num_workers_per_node,
                            proof_interval,
                            status_callback_arc.clone(),
                            event_sender.clone(),
                            shutdown.resubscribe(),
                            rotation_data.clone(),
                            active_threads.clone(),
                            node_tx,
                        ).await;
                        
                        // 这里不需要存储handle，因为我们只关心节点是否在运行
                        tokio::spawn(async move {
                            let _ = handle.await;
                            println!("⚠️ 节点工作线程已完成");
                        });
                        
                        // 添加一个短暂的延迟，避免同时启动太多节点
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                } else {
                    println!("🔄 节点管理器: 当前活动节点数量: {}, 最大并发数: {}, 无需启动新节点", 
                            current_active_count, max_concurrent);
                    nodes_to_start.clear(); // 清空启动队列
                }
            } else {
                println!("🔄 节点管理器: 当前活动节点数量: {} 已达到或超过最大并发数: {}, 不启动新节点", 
                        current_active_count, max_concurrent);
                nodes_to_start.clear(); // 清空启动队列
            }
        }
        
        tokio::select! {
            _ = shutdown.recv() => {
                println!("🛑 节点管理器收到关闭信号，正在退出");
                break;
            }
            cmd = node_rx.recv() => {
                match cmd {
                    Some(NodeManagerCommand::NodeStarted(node_id)) => {
                        println!("✅ 节点管理器: 节点-{} 已启动", node_id);
                        // 在单独作用域内更新状态，避免跨await持有锁
                        {
                            let mut active_threads_guard = active_threads.lock();
                            active_threads_guard.insert(node_id, true);
                        }
                        
                        // 同时发送到全局通道
                        let _ = global_tx.send(NodeManagerCommand::NodeStarted(node_id)).await;
                    }
                    Some(NodeManagerCommand::NodeStopped(node_id)) => {
                        println!("🛑 节点管理器: 节点-{} 已停止", node_id);
                        // 在单独作用域内更新状态，避免跨await持有锁
                        {
                            let mut active_threads_guard = active_threads.lock();
                            active_threads_guard.insert(node_id, false);
                        }
                        
                        // 同时发送到全局通道
                        let _ = global_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                        
                        // 立即检查是否有新节点需要启动
                        println!("🔄 节点管理器: 节点-{} 已停止，准备启动新节点", node_id);
                        
                        // 获取需要启动的节点列表
                        let new_nodes = get_nodes_to_start(&active_nodes, &active_threads).await;
                        
                        // 将新节点添加到启动队列
                        nodes_to_start.extend(new_nodes);
                        
                        // 更新最后检查时间
                        last_check_time = std::time::Instant::now();
                    }
                    None => {
                        // 只在第一次检测到通道关闭时输出警告，然后退出循环
                        static CHANNEL_CLOSED_WARNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                        
                        if !CHANNEL_CLOSED_WARNING.swap(true, std::sync::atomic::Ordering::SeqCst) {
                            println!("⚠️ 节点管理器: 主通信通道已关闭，切换到全局通道");
                        }
                        
                        // 短暂休眠，避免CPU占用过高
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
            _ = tokio::time::sleep(check_interval) => {
                // 定期检查是否有需要启动的新节点，但不要太频繁
                if last_check_time.elapsed() >= check_interval {
                    // 检查当前活动节点数量
                    let current_active_count = {
                        let active_threads_guard = active_threads.lock();
                        active_threads_guard.iter().filter(|(_, &active)| active).count()
                    };
                    
                    // 检查活动节点列表
                    let active_nodes_count = {
                        let active_nodes_guard = active_nodes.lock();
                        let count = active_nodes_guard.len();
                        
                        // 如果活动节点列表长度超过最大并发数，进行修正
                        if count > max_concurrent {
                            println!("⚠️ 节点管理器: 活动节点列表长度 ({}) 超过最大并发数 ({}), 进行修正", 
                                    count, max_concurrent);
                            
                            // 在这里不修改，因为我们还持有锁
                            true
                        } else {
                            false
                        }
                    };
                    
                    // 如果需要修正活动节点列表
                    if active_nodes_count {
                        let mut active_nodes_guard = active_nodes.lock();
                        // 保留前max_concurrent个节点
                        if active_nodes_guard.len() > max_concurrent {
                            active_nodes_guard.truncate(max_concurrent);
                            println!("✅ 节点管理器: 活动节点列表已修正为 {} 个节点", active_nodes_guard.len());
                        }
                    }
                    
                    // 输出当前状态
                    println!("🔄 节点管理器: 定期检查 - 活动线程数: {}, 最大并发数: {}", 
                            current_active_count, max_concurrent);
                    
                    // 获取需要启动的节点列表
                    let new_nodes = get_nodes_to_start(&active_nodes, &active_threads).await;
                    
                    // 只有在有新节点需要启动且活动节点数量低于最大并发数时才添加到启动队列
                    if !new_nodes.is_empty() && current_active_count < max_concurrent {
                        // 计算可以启动的节点数量
                        let nodes_to_start_count = (max_concurrent - current_active_count).min(new_nodes.len());
                        
                        if nodes_to_start_count > 0 {
                            println!("🔄 节点管理器: 发现 {} 个需要启动的新节点，将启动 {} 个", 
                                    new_nodes.len(), nodes_to_start_count);
                            
                            // 只添加需要的节点数量
                            nodes_to_start.extend(new_nodes.iter().take(nodes_to_start_count).cloned());
                        }
                    }
                    
                    // 更新最后检查时间
                    last_check_time = std::time::Instant::now();
                }
            }
        }
    }
}

// 获取需要启动的节点列表
async fn get_nodes_to_start(
    active_nodes: &Arc<Mutex<Vec<u64>>>,
    active_threads: &Arc<Mutex<HashMap<u64, bool>>>,
) -> Vec<u64> {
    // 获取需要启动的节点列表
    let active_nodes_guard = active_nodes.lock();
    let active_threads_guard = active_threads.lock();
    
    // 检查每个活动节点，找出没有运行的节点
    let mut to_start = Vec::new();
    for &node_id in active_nodes_guard.iter() {
        let is_running = active_threads_guard.get(&node_id).copied().unwrap_or(false);
        if !is_running {
            to_start.push(node_id);
        }
    }
    
    // 计算当前活动节点数量
    let active_count = active_threads_guard.iter().filter(|(_, &active)| active).count();
    
    if !to_start.is_empty() {
        println!("🔄 节点管理器: 发现 {} 个未运行的节点需要启动: {:?}", to_start.len(), to_start);
        println!("🔄 节点管理器: 当前活动节点数量: {}", active_count);
    }
    
    to_start
}

// 轮转到下一个节点的函数
async fn rotate_to_next_node(
    node_id: u64,
    rotation_data: &Option<(Arc<Mutex<Vec<u64>>>, Arc<AtomicU64>, Arc<Vec<u64>>, Arc<std::sync::atomic::AtomicBool>, Arc<Mutex<HashMap<u64, usize>>>, usize)>,
    reason: &str,
    node_tx: &mpsc::Sender<NodeManagerCommand>,
) -> (bool, Option<String>) {
    println!("\n📣 节点-{}: 尝试轮转 (原因: {})", node_id, reason);
    
    if let Some((active_nodes, _next_node_index, all_nodes, all_nodes_started, node_indices, max_concurrent)) = rotation_data {
        // 检查所有初始节点是否已启动
        if !all_nodes_started.load(std::sync::atomic::Ordering::SeqCst) {
            println!("⚠️ 节点-{}: 所有初始节点尚未启动完成，暂不轮转", node_id);
            return (false, Some(format!("⚠️ 节点-{}: 所有初始节点尚未启动完成，暂不轮转", node_id)));
        }
        
        // 获取当前节点的索引
        let node_idx_opt = {
            let node_indices_guard = node_indices.lock();
            node_indices_guard.get(&node_id).copied()
        };
        
        if let Some(node_idx) = node_idx_opt {
            // 计算下一个节点的索引：当前索引 + max_concurrent，如果超出范围则循环
            let next_idx = (node_idx + *max_concurrent) % all_nodes.len();
            let next_node_id = all_nodes[next_idx];
            
            // 确保不会轮转到自己
            let final_next_idx = if next_node_id == node_id && all_nodes.len() > 1 {
                // 如果轮转到自己且有其他节点可用，则选择下一个节点
                let alternative_idx = (next_idx + 1) % all_nodes.len();
                println!("⚠️ 节点-{}: 避免轮转到自己，改为使用索引 {}", node_id, alternative_idx);
                alternative_idx
            } else {
                next_idx
            };
            
            let final_next_node_id = all_nodes[final_next_idx];
            
            println!("📊 节点-{}: 当前索引: {}, 下一个索引: {}, 总节点数: {}", 
                    node_id, node_idx, final_next_idx, all_nodes.len());
            println!("🔄 节点-{}: 将轮转到节点-{} (索引: {})", node_id, final_next_node_id, final_next_idx);
            
            // 获取当前活跃节点列表并打印
            {
                let active_nodes_guard = active_nodes.lock();
                println!("📋 节点-{}: 轮转前活动节点列表: {:?}", node_id, *active_nodes_guard);
                println!("📋 节点-{}: 活动节点数量: {}, 最大并发数: {}", node_id, active_nodes_guard.len(), *max_concurrent);
            }
            
            // 查找当前节点在活动列表中的位置，并更新节点
            let pos_opt = {
                let mut active_nodes_guard = active_nodes.lock();
                println!("📋 节点-{}: 当前活动节点列表: {:?}", node_id, *active_nodes_guard);
                
                // 查找当前节点在活动列表中的位置
                let pos = active_nodes_guard.iter().position(|&id| id == node_id);
                
                if let Some(pos) = pos {
                    println!("✅ 节点-{}: 在活动列表中找到位置 {}", node_id, pos);
                    // 替换为新节点
                    active_nodes_guard[pos] = final_next_node_id;
                    println!("✅ 节点-{}: 已替换为节点-{}", node_id, final_next_node_id);
                    Some(pos)
                } else {
                    // 如果当前节点不在活动列表中，仍然尝试添加新节点
                    println!("\n⚠️ 节点-{}: 未在活动列表中找到", node_id);
                    
                    // 确保活动节点数量不超过max_concurrent
                    if active_nodes_guard.len() >= *max_concurrent {
                        println!("⚠️ 节点-{}: 活动节点数量已达到最大并发数 {}, 不添加新节点", node_id, *max_concurrent);
                        return (false, Some(format!("⚠️ 节点-{}: 活动节点数量已达到最大并发数 {}, 不添加新节点", node_id, *max_concurrent)));
                    }
                    
                    // 检查新节点是否已经在活动列表中
                    if active_nodes_guard.contains(&final_next_node_id) {
                        println!("⚠️ 节点-{}: 新节点-{} 已经在活动列表中，不重复添加", node_id, final_next_node_id);
                        return (false, Some(format!("⚠️ 节点-{}: 新节点-{} 已经在活动列表中，不重复添加", node_id, final_next_node_id)));
                    }
                    
                    // 如果活动列表未满，添加新节点
                    if active_nodes_guard.len() < all_nodes.len() {
                        active_nodes_guard.push(final_next_node_id);
                        println!("✅ 节点-{}: 已添加新节点-{} 到活动列表", node_id, final_next_node_id);
                        None
                    } else {
                        println!("⚠️ 节点-{}: 活动列表已满，无法添加新节点", node_id);
                        return (false, None);
                    }
                }
            }; // 锁在这里释放
            
            // 通知节点管理器当前节点已停止
            println!("📣 节点-{}: 正在通知节点管理器节点停止", node_id);
            
            // 添加重试机制，确保消息能够发送成功
            let mut retry_count = 0;
            let max_retries = 3;
            
            // 不再需要success变量，直接基于重试次数控制循环
            while retry_count < max_retries {
                // 确保消息发送成功 - 使用超时机制
                match tokio::time::timeout(
                    std::time::Duration::from_secs(2), 
                    node_tx.send(NodeManagerCommand::NodeStopped(node_id))
                ).await {
                    Ok(Ok(_)) => {
                        println!("📣 节点-{}: 已成功通知节点管理器节点停止", node_id);
                        // 成功发送消息，直接退出循环
                        break;
                    },
                    Ok(Err(e)) => {
                        retry_count += 1;
                        println!("⚠️ 节点-{}: 通知节点管理器失败 (尝试 {}/{}): {}", node_id, retry_count, max_retries, e);
                        
                        if retry_count >= max_retries {
                            println!("⚠️ 节点-{}: 通知节点管理器失败，达到最大重试次数", node_id);
                            // 即使通知失败，我们仍然认为轮转成功
                            println!("⚠️ 节点-{}: 通知失败，但活动节点列表已更新，继续轮转", node_id);
                        } else {
                            // 短暂等待后重试
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    },
                    Err(_) => {
                        retry_count += 1;
                        println!("⚠️ 节点-{}: 通知节点管理器超时 (尝试 {}/{})", node_id, retry_count, max_retries);
                        
                        if retry_count >= max_retries {
                            println!("⚠️ 节点-{}: 通知节点管理器超时，达到最大重试次数", node_id);
                            // 即使通知失败，我们仍然认为轮转成功
                            println!("⚠️ 节点-{}: 通知超时，但活动节点列表已更新，继续轮转", node_id);
                        } else {
                            // 短暂等待后重试
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    },
                }
            }
            
            // 即使通知失败，我们仍然认为轮转成功，因为活动节点列表已更新
            // 根据之前的查找结果生成状态消息
            let status_msg = if pos_opt.is_some() {
                format!("🔄 节点轮转: {} → {} (原因: {}) - 当前节点已处理完毕", node_id, final_next_node_id, reason)
            } else {
                format!("🔄 节点轮转: {} → {} (原因: {}) - 添加新节点", node_id, final_next_node_id, reason)
            };
            
            println!("\n{}\n", status_msg); // 添加明显的控制台输出
            
            // 等待一小段时间，确保节点管理器有时间处理消息
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            
            return (true, Some(status_msg));
        } else {
            println!("⚠️ 节点-{}: 未找到节点索引，无法轮转", node_id);
            return (false, None);
        }
    } else {
        // 轮转功能未启用
        println!("\n⚠️ 节点-{}: 轮转功能未启用或配置错误，无法轮转 (原因: {})\n", node_id, reason);
    }
    println!("❌ 节点-{}: 轮转失败", node_id);
    (false, None)
}

// 启动单个节点工作线程
async fn start_node_worker(
    node_id: u64,
    environment: Environment,
    proxy_file: Option<String>,
    num_workers_per_node: usize,
    proof_interval: u64,
    status_callback_arc: Option<Arc<Box<dyn Fn(u64, String) + Send + Sync + 'static>>>,
    event_sender: mpsc::Sender<Event>,
    shutdown: broadcast::Receiver<()>,
    rotation_data: Option<(Arc<Mutex<Vec<u64>>>, Arc<AtomicU64>, Arc<Vec<u64>>, Arc<std::sync::atomic::AtomicBool>, Arc<Mutex<HashMap<u64, usize>>>, usize)>,
    active_threads: Arc<Mutex<HashMap<u64, bool>>>,
    node_tx: mpsc::Sender<NodeManagerCommand>,
) -> JoinHandle<()> {
    // 获取密钥
    let signing_key = match crate::key_manager::load_or_generate_signing_key() {
        Ok(key) => key,
        Err(e) => {
            warn!("节点 {} 加载签名密钥失败: {}", node_id, e);
            // 使用Arc包装的回调
            if let Some(callback_arc) = &status_callback_arc {
                callback_arc(node_id, format!("加载密钥失败: {}", e));
            }
            
            // 返回一个已完成的JoinHandle
            return tokio::spawn(async {});
        }
    };
    
    // 使用增强版客户端
    let enhanced_orchestrator = if let Some(ref proxy_file) = proxy_file {
        EnhancedOrchestratorClient::new_with_proxy(environment.clone(), Some(proxy_file.as_str()))
    } else {
        EnhancedOrchestratorClient::new(environment.clone())
    };
    
    let client_id = format!("{:x}", md5::compute(node_id.to_le_bytes()));

    // 为每个任务克隆Arc包装的回调
    let node_callback = match &status_callback_arc {
        Some(callback_arc) => {
            // 克隆Arc，不是内部的回调函数
            let callback_arc_clone = Arc::clone(callback_arc);
            // 创建一个新的闭包，捕获Arc克隆
            Some(Box::new(move |node_id: u64, status: String| {
                callback_arc_clone(node_id, status);
            }) as Box<dyn Fn(u64, String) + Send + Sync + 'static>)
        }
        None => None
    };
    
    let event_sender_clone = event_sender.clone();
    let node_tx_clone = node_tx.clone();
    let active_threads_clone = active_threads.clone();
    
    // 启动节点工作线程
    let handle = tokio::spawn(async move {
        // 在单独的作用域中更新活动线程状态，避免跨await持有锁
        {
            // 通知节点管理器节点已启动
            let _ = node_tx_clone.send(NodeManagerCommand::NodeStarted(node_id)).await;
            
            // 更新活动线程状态
            let mut active_threads_guard = active_threads_clone.lock();
            active_threads_guard.insert(node_id, true);
        } // 锁在这里释放
        
        // 运行节点
        run_memory_optimized_node(
            node_id,
            signing_key,
            enhanced_orchestrator,
            num_workers_per_node,
            proof_interval,
            environment,
            client_id,
            shutdown,
            node_callback,
            event_sender_clone,
            rotation_data,
            active_threads_clone,
            node_tx_clone,
        ).await;
    });
    
    handle
}

/// 内存优化的单节点运行函数 - 包含429错误处理和错误恢复功能
async fn run_memory_optimized_node(
    node_id: u64,
    signing_key: SigningKey,
    orchestrator: EnhancedOrchestratorClient,
    _num_workers: usize,
    proof_interval: u64,
    environment: Environment,
    client_id: String,
    mut shutdown: broadcast::Receiver<()>,
    status_callback: Option<Box<dyn Fn(u64, String) + Send + Sync + 'static>>,
    event_sender: mpsc::Sender<Event>,
    rotation_data: Option<(Arc<Mutex<Vec<u64>>>, Arc<AtomicU64>, Arc<Vec<u64>>, Arc<std::sync::atomic::AtomicBool>, Arc<Mutex<HashMap<u64, usize>>>, usize)>,
    _active_threads: Arc<Mutex<HashMap<u64, bool>>>,
    node_tx: mpsc::Sender<NodeManagerCommand>,
) {
    // 创建一个停止标志，用于强制退出循环
    let should_stop = Arc::new(AtomicBool::new(false));
    let should_stop_clone = should_stop.clone();
    
    // 创建一个任务来监听停止信号
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        should_stop_clone.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    
    const MAX_SUBMISSION_RETRIES: usize = 8; // 增加到8次，特别是针对429错误
    const MAX_TASK_RETRIES: usize = 5; // 增加到5次
    const MAX_429_RETRIES: usize = 12; // 专门针对429错误的重试次数
    const MAX_CONSECUTIVE_429S_BEFORE_ROTATION: u32 = 1; // 连续429错误达到此数量时轮转（改为1）
    let mut _consecutive_failures = 0; // 改为_consecutive_failures
    let mut proof_count = 0;
    let mut consecutive_429s = 0; // 跟踪连续429错误
    
    // 使用传入的事件发送器
    let event_sender = event_sender.clone();
    
    // 创建节点速率限制跟踪器
    let rate_limit_tracker = online::NodeRateLimitTracker::new();
    
    // 更新节点状态
    let update_status = move |status: String| {
        if let Some(callback) = &status_callback {
            callback(node_id, status.clone());
        }
    };
    
    // 发送事件到UI
    let send_event = move |msg: String, event_type: crate::events::EventType| {
        let event_sender = event_sender.clone();
        tokio::spawn(async move {
            let _ = event_sender
                .send(Event::proof_submitter(msg, event_type))
                .await;
        });
    };
    
    update_status(format!("🚀 启动中"));
    
    // 通知节点管理器节点已启动
    let _ = node_tx.send(NodeManagerCommand::NodeStarted(node_id)).await;
    
    loop {
        // 检查停止标志
        if should_stop.load(std::sync::atomic::Ordering::SeqCst) {
            update_status("🛑 收到停止信号，正在停止...".to_string());
            // 通知节点管理器当前节点已停止
            let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
            println!("🛑 节点-{}: 强制停止", node_id);
            break;
        }
        
        // 首先检查关闭信号
        if shutdown.try_recv().is_ok() {
            update_status("已停止".to_string());
            // 通知节点管理器当前节点已停止
            let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
            break;
        }
        
        // 检查内存压力
        if check_memory_pressure() {
            update_status("⚠️ 检测到内存压力，执行清理...".to_string());
            perform_memory_cleanup();
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        // 获取内存碎片整理器状态
        let defragmenter = get_defragmenter();
        if defragmenter.should_defragment().await {
            update_status(format!("🧹 执行内存碎片整理..."));
            let result = defragmenter.defragment().await;
            update_status(format!("内存: {:.1}% → {:.1}% (释放 {:.1}%)",
                             result.memory_before * 100.0,
                             result.memory_after * 100.0,
                             result.memory_freed_percentage()));
        }
        
        let timestamp = get_timestamp_efficient();
        let mut attempt = 1;
        let _success = false; // 移除可变性，使用下划线前缀标记
        
        // 尝试获取任务并生成证明
        while attempt <= MAX_TASK_RETRIES {
            update_status(format!("[{}] 获取任务 ({}/{})", timestamp, attempt, MAX_TASK_RETRIES));
            
            let verifying_key = signing_key.verifying_key();
            match orchestrator.get_task(&node_id.to_string(), &verifying_key).await {
                Ok(task) => {
                    // 成功获取任务，重置429计数
                    rate_limit_tracker.reset_429_count(node_id).await;
                    consecutive_429s = 0; // 重置连续429计数
                    
                    // 获取节点成功次数
                    let success_count = rate_limit_tracker.get_success_count(node_id).await;
                    
                    // 获取任务成功
                    let timestamp = get_timestamp_efficient();
                    
                    // 更新状态显示成功次数
                    update_status(format!("[{}] 获取任务 ({}/5) (成功: {}次)", timestamp, attempt + 1, success_count));
                    
                    // 检查是否有该任务的缓存证明
                    if let Some((cached_proof_bytes, cached_proof_hash, attempts)) = orchestrator.get_cached_proof(&task.task_id) {
                        // 有缓存的证明，直接尝试提交
                        update_status(format!("[{}] 使用缓存证明重试提交 (尝试次数: {})", timestamp, attempts + 1));
                        
                        // 针对缓存的证明，我们可以进行更多次数的重试，特别是429错误
                        let mut retry_count = 0;
                        let mut rate_limited = false;
                        
                        // 对于缓存的证明，我们可以更积极地重试
                        while retry_count < MAX_429_RETRIES {
                            match orchestrator.submit_proof(&task.task_id, &cached_proof_hash, cached_proof_bytes.clone(), signing_key.clone()).await {
                                Ok(_) => {
                                    // 成功提交证明
                                    proof_count += 1;
                                    _consecutive_failures = 0;
                                    // 使用下划线前缀标记可能未使用的变量
                                    let _success = true; // 设置成功状态
                                    consecutive_429s = 0; // 重置连续429计数
                                    
                                    // 重置429计数
                                    rate_limit_tracker.reset_429_count(node_id).await;
                                    
                                    // 增加成功计数
                                    let success_count = rate_limit_tracker.increment_success_count(node_id).await;
                                    
                                    let msg = format!("[{}] ✅ 缓存证明提交成功! 证明 #{} 完成 (成功: {}次)", timestamp, proof_count, success_count);
                                    update_status(msg.clone());
                                    
                                    // 确保使用正确的事件类型记录成功
                                    send_event(format!("Proof submitted successfully #{}", proof_count), crate::events::EventType::ProofSubmitted);
                                    
                                    // 如果启用了轮转功能，成功提交后轮转到下一个节点
                                    let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "成功提交证明", &node_tx).await;
                                    if should_rotate {
                                        if let Some(msg) = status_msg {
                                            update_status(msg);
                                        }
                                        // 发送一个显式的停止消息，确保节点真正停止
                                        let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                                        println!("🛑 节点-{}: 轮转后显式停止", node_id);
                                        
                                        // 设置停止标志
                                        should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                        
                                        // 强制退出当前节点的处理循环
                                        return;
                                    }
                                    
                                    break;
                                }
                                Err(e) => {
                                    let error_str = e.to_string();
                                    if error_str.contains("RATE_LIMITED") || error_str.contains("429") {
                                        // 速率限制错误 - 使用随机等待时间
                                        rate_limited = true;
                                        let wait_time = 30 + rand::random::<u64>() % 31; // 30-60秒随机
                                        
                                        // 增加节点的429计数
                                        let count = rate_limit_tracker.increment_429_count(node_id).await;
                                        consecutive_429s += 1; // 增加连续429计数
                                        
                                        update_status(format!("[{}] 🚫 速率限制 (429) - 等待 {}s (重试 {}/{}, 连续429: {}次)", 
                                            timestamp, wait_time, retry_count + 1, MAX_429_RETRIES, count));
                                        
                                        // 如果启用了轮转功能且连续429错误达到阈值，轮转到下一个节点
                                        if consecutive_429s >= MAX_CONSECUTIVE_429S_BEFORE_ROTATION {
                                            println!("\n⚠️ 节点-{}: 连续429错误达到{}次，触发轮转 (阈值: {})\n", 
                                                node_id, consecutive_429s, MAX_CONSECUTIVE_429S_BEFORE_ROTATION);
                                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "连续429错误", &node_tx).await;
                                            if should_rotate {
                                                if let Some(msg) = status_msg {
                                                    update_status(msg);
                                                }
                                                // 发送一个显式的停止消息，确保节点真正停止
                                                let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                                                println!("🛑 节点-{}: 轮转后显式停止", node_id);
                                                
                                                // 设置停止标志
                                                should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                                
                                                // 强制退出当前节点的处理循环
                                                return;
                                            }
                                        } else {
                                            println!("节点-{}: 连续429错误: {}次 (轮转阈值: {}次)", 
                                                node_id, consecutive_429s, MAX_CONSECUTIVE_429S_BEFORE_ROTATION);
                                        }
                                        
                                        tokio::time::sleep(Duration::from_secs(wait_time)).await;
                                        retry_count += 1;
                                        continue;
                                    } else if error_str.contains("409") || error_str.contains("CONFLICT") || error_str.contains("已提交") {
                                        // 证明已经被提交，视为成功
                                        proof_count += 1;
                                        _consecutive_failures = 0;
                                        // 使用下划线前缀标记可能未使用的变量
                                        let _success = true; // 设置成功状态
                                        consecutive_429s = 0; // 重置连续429计数
                                        
                                        // 重置429计数
                                        rate_limit_tracker.reset_429_count(node_id).await;
                                        
                                        // 获取成功计数（不增加计数，因为409表示已经被计数过了）
                                        let success_count = rate_limit_tracker.get_success_count(node_id).await;
                                        
                                        let msg = format!("[{}] ✅ 证明已被接受 (409) (成功: {}次)", timestamp, success_count);
                                        update_status(msg.clone());
                                        
                                        send_event(format!("Proof already accepted #{}", proof_count), crate::events::EventType::ProofSubmitted);
                                        
                                        // 如果启用了轮转功能，成功提交后轮转到下一个节点
                                        let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "证明已被接受", &node_tx).await;
                                        if should_rotate {
                                            if let Some(msg) = status_msg {
                                                update_status(msg);
                                            }
                                            return; // 结束当前节点的处理
                                        }
                                        
                                        break;
                                    } else {
                                        // 重置429计数（非429错误）
                                        rate_limit_tracker.reset_429_count(node_id).await;
                                        consecutive_429s = 0; // 重置连续429计数
                                        
                                        update_status(format!("[{}] ❌ 缓存证明提交失败: {}", timestamp, error_str));
                                        
                                        // 检查是否为404错误（任务未找到），如果是则不再重试
                                        if error_str.contains("404") || error_str.contains("NotFoundError") || error_str.contains("Task not found") {
                                            update_status(format!("[{}] 🔍 任务已不存在 (404)，停止重试并获取新任务", timestamp));
                                            retry_count = MAX_429_RETRIES; // 设置为最大值以跳出循环
                                            break; // 立即退出重试循环
                                        }
                                        
                                        // 如果不是429错误，我们不需要那么多重试
                                        if retry_count >= 2 {
                                            update_status(format!("[{}] 放弃缓存证明，尝试重新生成...", timestamp));
                                            break;
                                        }
                                        tokio::time::sleep(Duration::from_secs(2)).await;
                                        retry_count += 1;
                                    }
                                }
                            }
                        }
                        
                        // 如果成功提交或达到429重试上限但仍是速率限制，则继续下一个循环
                        if _success || (retry_count >= MAX_429_RETRIES && rate_limited) {
                            if !_success && rate_limited {
                                update_status(format!("[{}] ⚠️ 429重试次数已达上限，等待一段时间后再尝试", timestamp));
                                tokio::time::sleep(Duration::from_secs(60)).await; // 长时间等待
                            }
                            break;
                        }
                    }
                    
                    // 没有缓存或缓存提交失败，重新生成证明
                    update_status(format!("[{}] 正在生成证明...", timestamp));
                    
                    match crate::prover::authenticated_proving(&task, &environment, client_id.clone()).await {
                        Ok(proof) => {
                            // 证明生成成功，开始提交
                            update_status(format!("[{}] 正在提交证明...", timestamp));
                            
                            // 计算哈希
                    let mut hasher = sha3::Sha3_256::new();
                            // 将Proof转换为Vec<u8>
                            let proof_bytes = postcard::to_allocvec(&proof)
                                .unwrap_or_else(|_| Vec::new());
                            hasher.update(&proof_bytes);
                    let hash = hasher.finalize();
                    let proof_hash = format!("{:x}", hash);
                            
                            // 提交证明 - 克隆签名密钥以避免所有权问题
                            let mut retry_count = 0;
                            let mut rate_limited = false;
                            
                            while retry_count < MAX_SUBMISSION_RETRIES {
                                match orchestrator.submit_proof(&task.task_id, &proof_hash, proof_bytes.clone(), signing_key.clone()).await {
                                Ok(_) => {
                                    // 成功提交证明
                                    proof_count += 1;
                                    _consecutive_failures = 0;
                                    // 使用下划线前缀标记可能未使用的变量
                                    let _success = true; // 设置成功状态
                                    consecutive_429s = 0; // 重置连续429计数
                                    
                                    // 重置429计数
                                    rate_limit_tracker.reset_429_count(node_id).await;
                                    
                                    // 增加成功计数
                                    let success_count = rate_limit_tracker.increment_success_count(node_id).await;
                                    
                                    let msg = format!("[{}] ✅ 证明 #{} 完成 (成功: {}次)", timestamp, proof_count, success_count);
                                    update_status(msg.clone());
                                    
                                    // 确保使用正确的事件类型记录成功
                                    send_event(format!("Proof submitted successfully #{}", proof_count), crate::events::EventType::ProofSubmitted);
                                    
                                    println!("\n🔍 节点-{}: 证明提交成功，准备轮转...", node_id);
                                    println!("🔍 节点-{}: rotation_data是否存在: {}\n", node_id, rotation_data.is_some());
                                    
                                    // 如果启用了轮转功能，成功提交后轮转到下一个节点
                                    let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "成功提交证明", &node_tx).await;
                                    if should_rotate {
                                        if let Some(msg) = status_msg {
                                            update_status(msg);
                                        }
                                        // 发送一个显式的停止消息，确保节点真正停止
                                        let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                                        println!("🛑 节点-{}: 轮转后显式停止", node_id);
                                        
                                        // 设置停止标志
                                        should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                        
                                        // 强制退出当前节点的处理循环
                                        return;
                                    } else {
                                        println!("🔍 节点-{}: 轮转结果: should_rotate=false", node_id);
                                    }
                                    
                                    break;
                                }
                                Err(e) => {
                                    let error_str = e.to_string();
                                    if error_str.contains("RATE_LIMITED") || error_str.contains("429") {
                                        // 速率限制错误
                                        rate_limited = true;
                                        
                                        // 增加节点的429计数
                                        let count = rate_limit_tracker.increment_429_count(node_id).await;
                                        consecutive_429s += 1; // 增加连续429计数
                                        
                                        // 缓存证明以便后续重试
                                        orchestrator.cache_proof(&task.task_id, &proof_hash, &proof_bytes);
                                        
                                        let wait_time = 30 + rand::random::<u64>() % 31; // 30-60秒随机
                                        update_status(format!("[{}] 🚫 速率限制 (429) - 等待 {}s (重试 {}/{}, 连续429: {}次)", 
                                            timestamp, wait_time, retry_count + 1, MAX_SUBMISSION_RETRIES, count));
                                        
                                        // 如果启用了轮转功能且连续429错误达到阈值，轮转到下一个节点
                                        if consecutive_429s >= MAX_CONSECUTIVE_429S_BEFORE_ROTATION {
                                            println!("\n⚠️ 节点-{}: 连续429错误达到{}次，触发轮转 (阈值: {})\n", 
                                                node_id, consecutive_429s, MAX_CONSECUTIVE_429S_BEFORE_ROTATION);
                                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "连续429错误", &node_tx).await;
                                            if should_rotate {
                                                if let Some(msg) = status_msg {
                                                    update_status(msg);
                                                }
                                                // 发送一个显式的停止消息，确保节点真正停止
                                                let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                                                println!("🛑 节点-{}: 轮转后显式停止", node_id);
                                                
                                                // 设置停止标志
                                                should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                                
                                                // 强制退出当前节点的处理循环
                                                return;
                                            }
                                        } else {
                                            println!("节点-{}: 连续429错误: {}次 (轮转阈值: {}次)", 
                                                node_id, consecutive_429s, MAX_CONSECUTIVE_429S_BEFORE_ROTATION);
                                        }
                                        
                                        tokio::time::sleep(Duration::from_secs(wait_time)).await;
                                    } else if error_str.contains("409") || error_str.contains("CONFLICT") || error_str.contains("已提交") {
                                        // 证明已经被提交，视为成功
                                        proof_count += 1;
                                        _consecutive_failures = 0;
                                        // 使用下划线前缀标记可能未使用的变量
                                        let _success = true; // 设置成功状态
                                        consecutive_429s = 0; // 重置连续429计数
                                        
                                        // 重置429计数
                                        rate_limit_tracker.reset_429_count(node_id).await;
                                        
                                        // 获取成功计数（不增加计数，因为409表示已经被计数过了）
                                        let success_count = rate_limit_tracker.get_success_count(node_id).await;
                                        
                                        let msg = format!("[{}] ✅ 证明已被接受 (409) (成功: {}次)", timestamp, success_count);
                                        update_status(msg.clone());
                                        
                                        send_event(format!("Proof already accepted #{}", proof_count), crate::events::EventType::ProofSubmitted);
                                        
                                        // 如果启用了轮转功能，成功提交后轮转到下一个节点
                                        let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "证明已被接受", &node_tx).await;
                                        if should_rotate {
                                            if let Some(msg) = status_msg {
                                                update_status(msg);
                                            }
                                            return; // 结束当前节点的处理
                                        }
                                        
                                        break;
                                    } else {
                                        // 其他错误
                                        _consecutive_failures += 1;
                                        consecutive_429s = 0; // 重置连续429计数
                                        
                                        // 重置429计数
                                        rate_limit_tracker.reset_429_count(node_id).await;
                                        
                                        update_status(format!("[{}] ❌ 证明提交失败: {} (重试 {}/{})", 
                                            timestamp, error_str, retry_count + 1, MAX_SUBMISSION_RETRIES));
                                        
                                        // 检查是否为404错误（任务未找到），如果是则不再重试
                                        if error_str.contains("404") || error_str.contains("NotFoundError") || error_str.contains("Task not found") {
                                            update_status(format!("[{}] 🔍 任务已不存在 (404)，停止重试并获取新任务", timestamp));
                                            break; // 立即退出重试循环
                                        }
                                        
                                        // 缓存证明以便后续重试
                                        if retry_count == 0 {
                                            orchestrator.cache_proof(&task.task_id, &proof_hash, &proof_bytes);
                                        }
                                        
                                        tokio::time::sleep(Duration::from_secs(2)).await;
                                    }
                                    retry_count += 1;
                                }
                            }
                            }
                            
                            if _success || retry_count >= MAX_SUBMISSION_RETRIES {
                                if !_success {
                                    // 如果是由于速率限制而失败，等待更长时间
                                    if rate_limited {
                                        update_status(format!("[{}] ⚠️ 速率限制重试次数已达上限，等待一段时间后再尝试", timestamp));
                                        tokio::time::sleep(Duration::from_secs(60)).await;
                                    } else {
                                        update_status(format!("[{}] ⚠️ 提交重试次数已达上限，等待一段时间后再尝试", timestamp));
                                        tokio::time::sleep(Duration::from_secs(5)).await;
                                    }
                                }
                                break;
                            }
                        }
                        Err(e) => {
                            // 证明生成失败
                            _consecutive_failures += 1;
                            consecutive_429s = 0; // 重置连续429计数
                            
                            // 重置429计数
                            rate_limit_tracker.reset_429_count(node_id).await;
                            
                            update_status(format!("[{}] ❌ 证明生成失败: {}", timestamp, e));
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                    }
                    
                    // 无论成功与否，都退出尝试循环
                    break;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    if error_str.contains("RATE_LIMITED") || error_str.contains("429") {
                        // 速率限制错误
                        let count = rate_limit_tracker.increment_429_count(node_id).await;
                        consecutive_429s += 1; // 增加连续429计数
                        
                        let wait_time = 30 + rand::random::<u64>() % 31; // 30-60秒随机
                        update_status(format!("[{}] 🚫 速率限制 (429) - 等待 {}s (尝试 {}/{}, 连续429: {}次)", 
                            timestamp, wait_time, attempt, MAX_TASK_RETRIES, count));
                        
                        // 如果启用了轮转功能且连续429错误达到阈值，轮转到下一个节点
                        if consecutive_429s >= MAX_CONSECUTIVE_429S_BEFORE_ROTATION {
                            println!("\n⚠️ 节点-{}: 连续429错误达到{}次，触发轮转 (阈值: {})\n", 
                                node_id, consecutive_429s, MAX_CONSECUTIVE_429S_BEFORE_ROTATION);
                            
                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "连续429错误", &node_tx).await;
                            if should_rotate {
                                if let Some(msg) = status_msg {
                                    update_status(format!("{}\n🔄 节点已轮转，当前节点处理结束", msg));
                                }
                                return; // 结束当前节点的处理
                            } else {
                                println!("⚠️ 节点-{}: 轮转失败，继续使用当前节点", node_id);
                            }
                        } else {
                            println!("节点-{}: 连续429错误: {}次 (轮转阈值: {}次)", 
                                node_id, consecutive_429s, MAX_CONSECUTIVE_429S_BEFORE_ROTATION);
                        }
                        
                        tokio::time::sleep(Duration::from_secs(wait_time)).await;
                    } else if error_str.contains("404") || error_str.contains("NOT_FOUND") {
                        // 404错误 - 无可用任务
                        consecutive_429s = 0; // 重置连续429计数
                        
                        // 重置429计数
                        rate_limit_tracker.reset_429_count(node_id).await;
                        
                        update_status(format!("[{}] 🔍 无可用任务 (404) (尝试 {}/{})", 
                            timestamp, attempt, MAX_TASK_RETRIES));
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    } else {
                        // 其他错误
                        _consecutive_failures += 1;
                        consecutive_429s = 0; // 重置连续429计数
                        
                        // 重置429计数
                        rate_limit_tracker.reset_429_count(node_id).await;
                        
                        update_status(format!("[{}] ❌ 获取任务失败: {} (尝试 {}/{})", 
                            timestamp, error_str, attempt, MAX_TASK_RETRIES));
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                    attempt += 1;
                }
            }
        }
        
        // 如果所有尝试都失败，等待一段时间后再试
        if !_success && attempt > MAX_TASK_RETRIES {
            update_status(format!("[{}] ⚠️ 获取任务失败，等待后重试...", timestamp));
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        
        // 如果启用了证明间隔，等待指定时间
        if proof_interval > 0 {
            let wait_time = proof_interval + (rand::random::<u64>() % 2); // 添加0-1秒的随机变化
            update_status(format!("[{}] ⏱️ 等待 {}s 后继续...", timestamp, wait_time));
            tokio::time::sleep(Duration::from_secs(wait_time)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::orchestrator::MockOrchestrator;
    use crate::prover_runtime::{Event, MAX_COMPLETED_TASKS, online::fetch_prover_tasks};
    use crate::task::Task;
    use crate::task_cache::TaskCache;
    use std::time::Duration;
    use tokio::sync::{broadcast, mpsc};

    /// Creates a mock orchestrator client that simulates fetching tasks.
    fn get_mock_orchestrator_client() -> MockOrchestrator {
        let mut i = 0;
        let mut mock = MockOrchestrator::new();
        mock.expect_get_proof_task().returning_st(move |_, _| {
            // Simulate a task with dummy data
            let task = Task::new(i.to_string(), format!("Task {}", i), vec![1, 2, 3]);
            i += 1;
            Ok(task)
        });
        mock
    }

    #[tokio::test]
    // Should fetch and enqueue tasks from the orchestrator.
    async fn test_task_fetching() {
        let orchestrator_client = Box::new(get_mock_orchestrator_client());
        let signer_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signer_key.verifying_key();
        let node_id = 1234;

        let task_queue_size = 10;
        let (task_sender, mut task_receiver) = mpsc::channel::<Task>(task_queue_size);

        // Run task_master in a tokio task to stay in the same thread context
        let (shutdown_sender, _) = broadcast::channel(1); // Only one shutdown signal needed
        let (event_sender, _event_receiver) = mpsc::channel::<Event>(100);
        let shutdown_receiver = shutdown_sender.subscribe();
        let successful_tasks = TaskCache::new(MAX_COMPLETED_TASKS);

        let task_master_handle = tokio::spawn(async move {
            fetch_prover_tasks(
                node_id,
                verifying_key,
                orchestrator_client,
                task_sender,
                event_sender,
                shutdown_receiver,
                successful_tasks,
            )
            .await;
        });

        // Receive tasks
        let mut received = 0;
        for _i in 0..task_queue_size {
            match tokio::time::timeout(Duration::from_secs(2), task_receiver.recv()).await {
                Ok(Some(task)) => {
                    println!("Received task {}: {:?}", received, task);
                    received += 1;
                }
                Ok(None) => {
                    eprintln!("Channel closed unexpectedly");
                    break;
                }
                Err(_) => {
                    eprintln!("Timed out waiting for task {}", received);
                    break;
                }
            }
        }

        task_master_handle.abort();
    }
}
