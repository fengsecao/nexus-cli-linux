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
use std::sync::atomic::{AtomicU64, Ordering, AtomicBool, AtomicU32};
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
use std::time::Instant;
use std::future::Future;
use std::collections::HashSet;
use lazy_static;
use std::fs::OpenOptions;
use std::io::Write as IoWrite;

/// Maximum number of completed tasks to keep in memory. Chosen to be larger than the task queue size.
const MAX_COMPLETED_TASKS: usize = 500;

// 添加全局调试输出控制
// 设置为true时显示更多调试信息，false时只显示必要信息
// 对于有大量节点的情况，建议设置为false以减少输出
static VERBOSE_OUTPUT: AtomicBool = AtomicBool::new(false);

// 添加一个全局变量，用于完全禁止所有日志输出
static DISABLE_ALL_LOGS: AtomicBool = AtomicBool::new(false);

/// 设置全局输出详细程度
pub fn set_verbose_output(verbose: bool) {
    VERBOSE_OUTPUT.store(verbose, Ordering::SeqCst);
}

/// 获取当前输出详细程度
pub fn get_verbose_output() -> bool {
    VERBOSE_OUTPUT.load(Ordering::SeqCst)
}

/// 设置是否禁止所有日志输出
pub fn set_disable_all_logs(disable: bool) {
    DISABLE_ALL_LOGS.store(disable, Ordering::SeqCst);
}

/// 检查是否应该输出日志
pub fn should_log() -> bool {
    !DISABLE_ALL_LOGS.load(Ordering::SeqCst)
}

/// 条件性日志输出宏，只有在should_log()返回true时才输出
macro_rules! log_println {
    ($($arg:tt)*) => {
        if should_log() {
            println!($($arg)*);
        }
    };
}

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

/// 全局请求限流器 - 限制对服务器的请求频率
/// 
/// 动态调整机制:
/// - 初始速率: 每秒1个请求
/// - 如果检测到429错误: 降低10%速率 (例如: 1.0 -> 0.9 -> 0.81 ...)
/// - 如果请求成功: 增加10%速率 (例如: 1.0 -> 1.1 -> 1.21 ...)
/// - 速率限制范围: 最低每10秒1个请求 (0.1/秒), 最高每秒5个请求 (5.0/秒)
pub struct GlobalRateLimiter {
    last_request_time: Instant,
    request_interval: Duration,
    requests_per_second: f64,
    total_requests: u64,
}

impl GlobalRateLimiter {
    pub fn new(requests_per_second: f64) -> Self {
        let interval = Duration::from_secs_f64(1.0 / requests_per_second);
        if get_verbose_output() {
            println!("🚦 初始化全局请求限流器 - 每秒 {} 个请求，间隔 {:.2}ms", 
                    requests_per_second, interval.as_millis());
        }
        Self {
            last_request_time: Instant::now(),
            request_interval: interval,
            requests_per_second,
            total_requests: 0,
        }
    }
    
    /// 调整请求速率
    pub fn set_rate(&mut self, requests_per_second: f64) {
        self.requests_per_second = requests_per_second;
        self.request_interval = Duration::from_secs_f64(1.0 / requests_per_second);
        if get_verbose_output() {
            println!("🚦 调整全局请求限流器 - 每秒 {} 个请求，间隔 {:.2}ms", 
                    requests_per_second, self.request_interval.as_millis());
        }
    }
    
    /// 获取当前请求速率
    pub fn get_rate(&self) -> f64 {
        self.requests_per_second
    }
    
    /// 获取总请求数
    pub fn get_total_requests(&self) -> u64 {
        self.total_requests
    }
}

// 创建全局限流器实例 - 默认每秒3个请求，但会被用户设置覆盖
static GLOBAL_RATE_LIMITER: Lazy<Mutex<GlobalRateLimiter>> = Lazy::new(|| {
    // 检查环境变量中是否有初始速率设置
    let default_rate = std::env::var("NEXUS_INITIAL_RATE")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(3.0);
    
    if should_log() {
        println!("🚀 初始化全局请求限流器 - 使用默认值每秒 {} 个请求", default_rate);
    }
    
    Mutex::new(GlobalRateLimiter::new(default_rate))
});

// 全局429错误计数器
static RECENT_429_ERRORS: Lazy<AtomicU32> = Lazy::new(|| AtomicU32::new(0));
// 总429错误计数器（从程序启动起累计，不重置）
static TOTAL_429_ERRORS: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));

// 速率配置
static MIN_RATE: Lazy<Mutex<Option<f64>>> = Lazy::new(|| Mutex::new(None));
static MAX_RATE: Lazy<Mutex<Option<f64>>> = Lazy::new(|| Mutex::new(None));
static USER_INITIAL_RATE: Lazy<Mutex<Option<f64>>> = Lazy::new(|| Mutex::new(None));

// 记录用户是否明确设置了初始速率
static INITIAL_RATE_SET: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

/// 设置最低请求速率
pub fn set_min_request_rate(rate: f64) {
    let mut min_rate = MIN_RATE.lock();
    *min_rate = Some(rate);
    if get_verbose_output() {
        log_println!("🚦 设置最低请求速率: 每秒 {} 个请求", rate);
    }
}

/// 设置最高请求速率
pub fn set_max_request_rate(rate: f64) {
    let mut max_rate = MAX_RATE.lock();
    *max_rate = Some(rate);
    if get_verbose_output() {
        log_println!("🚦 设置最高请求速率: 每秒 {} 个请求", rate);
    }
}

/// 增加429错误计数
pub fn increment_429_error_count() {
    RECENT_429_ERRORS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    TOTAL_429_ERRORS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// 获取429错误计数（不重置）
pub fn get_429_error_count() -> u32 {
    RECENT_429_ERRORS.load(std::sync::atomic::Ordering::SeqCst)
}

/// 获取累计429错误计数（不重置）
pub fn get_total_429_error_count() -> u64 {
    TOTAL_429_ERRORS.load(std::sync::atomic::Ordering::SeqCst)
}

/// 获取并重置429错误计数
#[allow(dead_code)]
pub fn get_and_reset_429_error_count() -> u32 {
    RECENT_429_ERRORS.swap(0, std::sync::atomic::Ordering::SeqCst)
}

/// 重置429错误计数
pub fn reset_429_error_count() {
    RECENT_429_ERRORS.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// 全局API请求函数 - 所有对服务器的请求都应该通过这个函数
pub async fn make_api_request<F, T>(request_func: F) -> T 
where 
    F: Future<Output = T>,
{
    // 等待限流器允许发送请求
    {
        // 在单独的作用域中获取锁并等待
        let wait_duration = {
            let mut limiter = GLOBAL_RATE_LIMITER.lock();
            let now = Instant::now();
            let elapsed = now.duration_since(limiter.last_request_time);
            
            // 计算需要等待的时间
            let wait_time = if elapsed < limiter.request_interval {
                limiter.request_interval - elapsed
            } else {
                Duration::from_secs(0)
            };
            
            // 更新上次请求时间和总请求数
            limiter.last_request_time = now;
            limiter.total_requests += 1;
            
            // 每10个请求输出一次日志，避免日志过多
            if limiter.total_requests % 10 == 0 && get_verbose_output() {
                println!("🚦 全局限流: 等待 {:.2}ms 后发送下一个请求 (总请求数: {})", 
                        wait_time.as_millis(), limiter.total_requests);
            }
            
            wait_time
        }; // 锁在这里释放
        
        // 锁释放后再等待
        if wait_duration.as_nanos() > 0 {
            tokio::time::sleep(wait_duration).await;
        }
    }
    
    // 发送请求
    request_func.await
}

/// 调整全局请求速率
pub fn set_global_request_rate(requests_per_second: f64) {
    let mut limiter = GLOBAL_RATE_LIMITER.lock();
    limiter.set_rate(requests_per_second);
    
    // 标记用户已设置初始速率，这会防止其他地方重置它
    INITIAL_RATE_SET.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// 获取全局请求统计信息
pub fn get_global_request_stats() -> (f64, u64) {
    let limiter = GLOBAL_RATE_LIMITER.lock();
    (limiter.get_rate(), limiter.get_total_requests())
}

/// 全局活跃节点数量限制器
pub static GLOBAL_ACTIVE_NODES: Lazy<Mutex<HashSet<u64>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// 获取当前全局活跃节点数量
pub fn get_global_active_node_count() -> usize {
    let nodes = GLOBAL_ACTIVE_NODES.lock();
    nodes.len()
}

/// 添加节点到全局活跃节点集合
pub fn add_global_active_node(node_id: u64) -> bool {
    let mut nodes = GLOBAL_ACTIVE_NODES.lock();
    let result = nodes.insert(node_id);
    log_println!("🌍 全局活跃节点: 添加节点-{} ({}), 当前活跃节点数量: {}", 
            node_id, if result { "新增" } else { "已存在" }, nodes.len());
    result
}

/// 从全局活跃节点集合移除节点
pub fn remove_global_active_node(node_id: u64) -> bool {
    let mut nodes = GLOBAL_ACTIVE_NODES.lock();
    let result = nodes.remove(&node_id);
    log_println!("🌍 全局活跃节点: 移除节点-{} ({}), 当前活跃节点数量: {}", 
            node_id, if result { "成功" } else { "不存在" }, nodes.len());
    result
}

/// 检查节点是否在全局活跃集合中
pub fn is_node_globally_active(node_id: u64) -> bool {
    let nodes = GLOBAL_ACTIVE_NODES.lock();
    nodes.contains(&node_id)
}

/// 清理全局活跃节点集合，确保只保留真正活跃的节点
pub fn sync_global_active_nodes(active_threads: &Arc<Mutex<HashMap<u64, bool>>>, max_concurrent: usize) {
    let mut nodes = GLOBAL_ACTIVE_NODES.lock();
    
    // 获取当前真正活跃的节点
    let active_nodes: HashSet<u64> = {
        let threads_guard = active_threads.lock();
        threads_guard.iter()
            .filter(|pair| *pair.1)
            .map(|(&id, _)| id)
            .collect()
    };
    
    // 如果活跃节点为空但全局节点不为空，不再保留全局节点，而是进行警告并清空
    if active_nodes.is_empty() && !nodes.is_empty() {
        log_println!("⚠️ 严重警告: 本地活跃节点为空，但全局有 {} 个活跃节点，执行强制清理", nodes.len());
        // 记录要清理的节点ID
        let nodes_to_clear: Vec<u64> = nodes.iter().copied().collect();
        for node_id in &nodes_to_clear {
            nodes.remove(node_id);
            log_println!("🌍 全局活跃节点同步 - 强制移除节点: {}", node_id);
        }
        log_println!("🌍 全局活跃节点同步 - 强制清理完成，当前活跃节点数量: 0");
        return;
    }
    
    // 增量更新全局活跃节点集合，而不是完全清空重建
    // 1. 移除不再活跃的节点
    let nodes_to_remove: Vec<u64> = nodes.iter()
        .filter(|node_id| !active_nodes.contains(node_id))
        .copied()
        .collect();
    
    let removed_count = nodes_to_remove.len();
    for node_id in &nodes_to_remove {
        nodes.remove(node_id);
        log_println!("🌍 全局活跃节点同步 - 移除不活跃节点: {}", node_id);
    }
    
    // 2. 添加新的活跃节点，但确保不超过max_concurrent
    let mut added_count = 0;
    for &node_id in active_nodes.iter() {
        if !nodes.contains(&node_id) && nodes.len() < max_concurrent {
            nodes.insert(node_id);
            added_count += 1;
            log_println!("🌍 全局活跃节点同步 - 添加新活跃节点: {}", node_id);
        }
    }
    
    // 如果全局活跃节点数量为0，但有本地活跃节点，强制添加
    if nodes.is_empty() && !active_nodes.is_empty() {
        log_println!("⚠️ 全局活跃节点集合为空，但有本地活跃节点，强制添加");
        for &node_id in active_nodes.iter().take(max_concurrent) {
            nodes.insert(node_id);
            added_count += 1;
            log_println!("🌍 全局活跃节点同步 - 强制添加节点: {}", node_id);
        }
    }
    
    log_println!("🌍 全局活跃节点同步 - 移除了 {} 个不活跃节点，添加了 {} 个新活跃节点，当前活跃节点数量: {}/{}", 
            removed_count, added_count, nodes.len(), max_concurrent);
    
    // 确保节点真正启动 - 将全局活跃节点集合中的节点在active_threads中标记为需要启动
    if !nodes.is_empty() {
        let mut threads_guard = active_threads.lock();
        let mut nodes_to_start = 0;
        
        for &node_id in nodes.iter() {
            if !threads_guard.get(&node_id).copied().unwrap_or(false) {
                threads_guard.insert(node_id, false); // 标记为需要启动
                nodes_to_start += 1;
            }
        }
        
        if nodes_to_start > 0 {
            log_println!("🚀 全局活跃节点同步 - 标记 {} 个节点需要启动", nodes_to_start);
        }
    }
}

// 添加全局节点状态跟踪器
lazy_static::lazy_static! {
    static ref NODE_STATES: Mutex<HashMap<u64, String>> = Mutex::new(HashMap::new());
}

/// 设置节点的当前状态
pub fn set_node_state(node_id: u64, state: &str) {
    let mut states = NODE_STATES.lock();
    states.insert(node_id, state.to_string());
}

/// 获取节点的当前状态
pub fn get_node_state(node_id: u64) -> String {
    let states = NODE_STATES.lock();
    states.get(&node_id).cloned().unwrap_or_else(|| "等待任务".to_string())
}

/// 将每次429记录到文件，便于后续排查
pub fn record_429_event(node_id: u64, reason: &str) {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let line = format!("{} | node={} | {}\n", ts, node_id, reason);
    let path = std::env::var("NEXUS_429_LOG").unwrap_or_else(|_| "429_nodes.log".to_string());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
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
    _start_delay: f64,
    proof_interval: u64,
    environment: Environment,
    shutdown: broadcast::Receiver<()>,
    status_callback: Option<Box<dyn Fn(u64, String) + Send + Sync + 'static>>,
    proxy_file: Option<String>,
    rotation: bool,
    max_concurrent: usize, // 添加max_concurrent参数
    initial_rate: Option<f64>,
    min_rate: Option<f64>,
    max_rate: Option<f64>,
) -> (mpsc::Receiver<Event>, Vec<JoinHandle<()>>) {
    // Worker事件
    let (event_sender, event_receiver) = mpsc::channel::<Event>(EVENT_QUEUE_SIZE);
    let mut join_handles = Vec::new();
    let defragmenter = get_defragmenter();
    
    // 设置初始请求速率（如果提供）
    if let Some(rate) = initial_rate {
        // 保存用户设置的初始速率
        {
            let mut user_rate = USER_INITIAL_RATE.lock();
            *user_rate = Some(rate);
        }
        
        // 强制设置全局请求速率为用户指定的值
        set_global_request_rate(rate);
        
        // 记录实际设置后的值，确认是否正确
        let actual_rate = {
            let limiter = GLOBAL_RATE_LIMITER.lock();
            limiter.get_rate()
        };
        
        // 保存用户设置的初始速率，用于自适应调整时参考
        {
            let mut min_rate_lock = MIN_RATE.lock();
            if min_rate_lock.is_none() {
                // 如果用户没有明确设置最小速率，则将其设置为初始速率的20%
                *min_rate_lock = Some(rate * 0.2);
            }
            
            let mut max_rate_lock = MAX_RATE.lock();
            if max_rate_lock.is_none() {
                // 如果用户没有明确设置最大速率，则将其设置为初始速率的500%
                *max_rate_lock = Some(rate * 5.0);
            }
        }
        
        // 输出详细的日志，确认速率已被正确设置
        log_println!("🚦 用户设置初始请求速率: {} 每秒，实际设置为: {} 每秒", 
                    rate, actual_rate);
                    
        // 将用户设置的初始速率保存到环境变量中，以便后续组件使用
        unsafe {
            std::env::set_var("NEXUS_INITIAL_RATE", rate.to_string());
        }
    } else {
        // 如果用户没有提供初始速率，也输出当前使用的默认值
        let current_rate = {
            let limiter = GLOBAL_RATE_LIMITER.lock();
            limiter.get_rate()
        };
        log_println!("🚦 使用默认请求速率: 每秒 {} 个请求", current_rate);
    }
    
    // 设置最低请求速率（如果提供）
    if let Some(rate) = min_rate {
        set_min_request_rate(rate);
        log_println!("🚦 设置最低请求速率: 每秒 {} 个请求", rate);
    }
    
    // 设置最高请求速率（如果提供）
    if let Some(rate) = max_rate {
        set_max_request_rate(rate);
        log_println!("🚦 设置最高请求速率: 每秒 {} 个请求", rate);
    }
    
    // 显示当前速率设置
    {
        let min_rate_value = MIN_RATE.lock().unwrap_or(0.5);
        let max_rate_value = MAX_RATE.lock().unwrap_or(20.0);
        let current_rate = GLOBAL_RATE_LIMITER.lock().get_rate();
        
        log_println!("📊 请求速率配置: 当前={:.1}, 最小={:.1}, 最大={:.1} 请求/秒", 
                   current_rate, min_rate_value, max_rate_value);
    }
    
    // 将回调函数包装在Arc中，这样可以在多个任务之间共享
    let status_callback_arc = status_callback.map(Arc::new);
    
    // 预初始化证明器 - 确保它们被共享
    let _ = crate::prover::get_or_create_default_prover().await;
    let _ = crate::prover::get_or_create_initial_prover().await;
    
    // 增加初始延迟，避免一次性启动太多节点导致429错误
    let initial_delay = 1.0; // 1秒初始延迟
    log_println!("等待初始延迟 {:.1}秒...", initial_delay);
    tokio::time::sleep(std::time::Duration::from_secs_f64(initial_delay)).await;
    
    // 计算实际并发数（最大并发数与节点数量的较小值）
    let actual_concurrent = max_concurrent.min(nodes.len());
    if get_verbose_output() {
        log_println!("🧮 设置的并发数: {}, 实际并发数: {}", max_concurrent, actual_concurrent);
    }
    
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
    let (node_tx, _node_rx) = mpsc::channel::<NodeManagerCommand>(100);
    
    // 保存发送端，以便后续使用
    let _node_tx_for_workers = node_tx.clone();
    
    // 如果启用了轮转功能，创建节点队列和活动节点跟踪器
    let all_nodes = Arc::new(nodes.clone());
    let rotation_data = if rotation {
        if get_verbose_output() {
            log_println!("🔄 启用节点轮转功能 - 总节点数: {}", nodes.len());
        }
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
            
            log_println!("🔄 初始化活动节点队列 - 最大并发数: {}, 总节点数: {}", actual_concurrent, nodes.len());
            
            // 只添加前actual_concurrent个节点到活动队列
            for (idx, node_id) in sorted_nodes.iter().take(actual_concurrent) {
                // 确保不会添加超过最大并发数的节点
                if active_nodes_guard.len() >= actual_concurrent {
                    log_println!("⚠️ 活动节点队列已达到最大并发数 {}, 不再添加节点", actual_concurrent);
                    break;
                }
                
                // 确保节点不重复添加
                if !active_nodes_guard.contains(node_id) {
                    active_nodes_guard.push(*node_id);
                    if get_verbose_output() {
                        log_println!("🔄 添加节点-{} 到活动节点队列 (索引: {})", node_id, idx);
                    }
                } else {
                    log_println!("⚠️ 节点-{} 已在活动队列中，跳过 (索引: {})", node_id, idx);
                }
                
                // 更新节点索引映射
                node_indices_guard.insert(*node_id, *idx);
                
                // 标记节点为未启动
                let mut active_threads_guard = active_threads.lock();
                active_threads_guard.insert(*node_id, false);
            }
            
            // 初始化剩余节点的索引映射
            for (idx, node_id) in sorted_nodes.iter().skip(actual_concurrent) {
                node_indices_guard.insert(*node_id, *idx);
                
                // 确保所有节点都在active_threads中初始化
                let mut active_threads_guard = active_threads.lock();
                if !active_threads_guard.contains_key(node_id) {
                    active_threads_guard.insert(*node_id, false);
                }
            }
            
            if get_verbose_output() {
                log_println!("🔄 初始活动节点队列: {:?} (大小: {})", *active_nodes_guard, active_nodes_guard.len());
                log_println!("🔄 下一个节点索引: {}", next_node_index.load(std::sync::atomic::Ordering::SeqCst));
                log_println!("🔄 最大并发数: {}, 总节点数: {}", actual_concurrent, nodes.len());
            }
            
            // 最后再次确认活动节点数量不超过最大并发数
            if active_nodes_guard.len() > actual_concurrent {
                log_println!("⚠️ 活动节点队列超出最大并发数 ({} > {}), 进行截断", 
                        active_nodes_guard.len(), actual_concurrent);
                active_nodes_guard.truncate(actual_concurrent);
                log_println!("✅ 活动节点队列已截断至 {} 个节点", active_nodes_guard.len());
            }
        } // 锁在这里释放
        
        Some((active_nodes.clone(), next_node_index.clone(), all_nodes.clone(), all_nodes_started.clone(), node_indices.clone(), actual_concurrent))
    } else {
        log_println!("⚠️ 节点轮转功能未启用");
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
            let rotation_data_for_manager = rotation_data.clone();
            
            // 打印初始活动节点列表
            {
                let active_nodes_guard = active_nodes_clone.lock();
                if get_verbose_output() {
                    log_println!("🔄 启动节点管理器线程 - 初始活动节点列表: {:?}", *active_nodes_guard);
                }
            }
            
            if get_verbose_output() {
                log_println!("🔄 启动节点管理器线程");
            }
            
            // 创建一个新的通道，用于节点管理器
            let (node_tx, node_rx) = mpsc::channel::<NodeManagerCommand>(100);
            
            // 保存发送端，供其他地方使用
            let node_tx_for_workers = node_tx.clone();
            
            // 使用node_tx_for_workers来启动节点
            {
                // 获取活动节点列表
                let active_nodes_guard = active_nodes_clone.lock();
                
                for node_id in active_nodes_guard.iter().copied().take(actual_concurrent) {
                    log_println!("🚀 节点管理器: 初始启动节点-{}", node_id);
                    
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
                        node_tx_for_workers.clone(),
                    ).await;
                    
                    // 不需要存储句柄，因为它们会在完成时自动清理
                    tokio::spawn(async move {
                        let _ = handle.await;
                    });
                }
            }
            
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
                    node_rx,
                    rotation_data_for_manager,
                    node_tx_for_workers,
                ).await;
            });
            
            join_handles.push(manager_handle);
            
            // 启动一个定期任务，用于监控和调整请求速率
            let mut shutdown_monitor = shutdown.resubscribe();
            let monitor_handle = tokio::spawn(async move {
                let mut _consecutive_429s = 0;
                let mut consecutive_successes = 0;
                let check_interval = std::time::Duration::from_secs(30); // 每30秒检查一次
                
                // 获取当前速率，如果用户设置了初始速率则使用用户设置的值
                let mut current_rate = {
                    // 首先检查用户是否设置了初始速率
                    let user_rate = USER_INITIAL_RATE.lock();
                    if let Some(rate) = *user_rate {
                        // 用户设置了初始速率，使用它
                        log_println!("🚦 速率监控使用用户设置的初始速率: 每秒 {} 个请求", rate);
                        rate
                    } else {
                        // 没有用户设置，使用当前全局速率
                        let rate = GLOBAL_RATE_LIMITER.lock().get_rate();
                        log_println!("🚦 速率监控使用当前全局速率: 每秒 {} 个请求", rate);
                        rate
                    }
                };
                
                loop {
                    tokio::select! {
                        _ = shutdown_monitor.recv() => {
                            log_println!("🛑 请求速率监控任务收到关闭信号，正在退出");
                            break;
                        }
                        _ = tokio::time::sleep(check_interval) => {
                            // 获取当前请求统计信息
                            let (_rate, total_requests) = get_global_request_stats();
                            
                            // 检查最近是否有429错误（不重置计数器）
                            let recent_429s = get_429_error_count();
                            
                            if recent_429s > 0 {
                                // 如果有429错误，减慢请求速率 (降低10%)
                                _consecutive_429s += 1;
                                consecutive_successes = 0;
                                
                                                                        // 根据429错误数量按比例减少速率
                                // 3个429错误降低1%，4个降低2%，依此类推，最多10%
                                let errors_above_threshold = if recent_429s >= 3 { recent_429s - 2 } else { 0 };
                                let decrease_percent = f64::min(errors_above_threshold as f64 * 0.01, 0.1); // 最多减少10%
                                let min_rate = {
                                    let lock = MIN_RATE.lock();
                                    lock.unwrap_or(1.0) // 默认最低每1秒1个请求
                                };
                                current_rate = f64::max(current_rate * (1.0 - decrease_percent), min_rate);
                                set_global_request_rate(current_rate);
                                if get_verbose_output() {
                                    log_println!("⚠️ 检测到429错误 ({}个)，降低请求速率至每秒{}个 (降低{}%)", 
                                            recent_429s, current_rate, (decrease_percent * 100.0).round());
                                }
                                
                                // 重置429错误计数，避免重复计算
                                reset_429_error_count();
                            } else {
                                // 如果没有429错误，可以考虑逐渐增加请求速率
                                _consecutive_429s = 0;
                                consecutive_successes += 1;
                                
                                // 每次检查都增加速率，增加10%的速率
                                let max_rate = {
                                    let lock = MAX_RATE.lock();
                                    lock.unwrap_or(20.0) // 默认最高每秒20个请求
                                };
                                
                                // 计算新的速率，增加10%，不要使用较小的增幅
                                let new_rate = f64::min(current_rate * 1.1, max_rate);
                                
                                // 只有当新速率比当前速率高时才设置
                                if new_rate > current_rate {
                                    current_rate = new_rate;
                                    set_global_request_rate(current_rate);
                                    if get_verbose_output() {
                                        log_println!("✅ 无429错误，增加请求速率至每秒{}个 (增加10%)", current_rate);
                                    }
                                }
                                
                                // 重置成功计数，避免过大
                                if consecutive_successes >= 10 {
                                    consecutive_successes = 1;
                                }
                            }
                            
                            // 输出当前请求统计信息
                            if get_verbose_output() {
                                log_println!("📊 请求速率监控: 当前速率 = 每秒{}个请求, 总请求数 = {}", current_rate, total_requests);
                            } else if total_requests % 20 == 0 { // 即使不是详细模式，也每20个请求输出一次
                                log_println!("📊 当前请求速率: 每秒{}个请求 (总请求数: {})", current_rate, total_requests);
                            }
                        }
                    }
                }
            });
            
            join_handles.push(monitor_handle);
            
            // 创建一个任务来监控所有初始节点是否已启动
            let active_threads_monitor = active_threads.clone();
            let all_nodes_started_monitor = all_nodes_started_clone.clone();
            
            tokio::spawn(async move {
                // 先等待更长的时间，确保节点有足够时间启动
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                
                // 如果没有立即检测到活动节点，进入循环监控模式
                let mut attempts = 0;
                let max_attempts = 30; // 增加到30次尝试，确保有足够的时间
                
                loop {
                    attempts += 1;
                    
                    // 检查活动节点数量
                    let (active_count, total_active_threads) = {
                        let active_threads_guard = active_threads_monitor.lock();
                        let active_count = active_threads_guard.values().filter(|&&active| active).count();
                        (active_count, active_threads_guard.len())
                    };
                    
                    // 获取全局活跃节点数量
                    let global_active_count = get_global_active_node_count();
                    
                    // 输出当前活动线程信息
                    if attempts % 5 == 0 || attempts == 1 { // 减少日志输出频率
                        log_println!("🔄 节点启动监控: 当前活动节点数量: {}/{}, 全局活跃: {}, 尝试次数: {}/{}", 
                                active_count, total_active_threads, global_active_count, attempts, max_attempts);
                    }
                    
                    // 检查是否达到了最大并发数
                    if active_count >= max_concurrent {
                        // 设置所有节点已启动标志
                        all_nodes_started_monitor.store(true, std::sync::atomic::Ordering::SeqCst);
                        log_println!("🚀 所有初始节点已启动 ({}/{}), 可以开始轮转", 
                                active_count, max_concurrent);
                        break;
                    }
                    
                    // 如果尝试次数过多，强制标记为已启动
                    if attempts >= max_attempts {
                        all_nodes_started_monitor.store(true, std::sync::atomic::Ordering::SeqCst);
                        log_println!("⚠️ 节点启动监控: 达到最大尝试次数 ({}), 强制标记所有节点已启动", max_attempts);
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
        nodes.iter().take(actual_concurrent).copied().collect::<Vec<u64>>()
    };
    
    log_println!("🔄 准备按顺序启动以下节点: {:?}", active_nodes_list);

    // 按序启动各节点
    for (index, node_id) in active_nodes_list.iter().enumerate() {
        // 减少输出，只显示关键信息
        if index % 10 == 0 || index == active_nodes_list.len() - 1 {
            log_println!("启动节点 {} (第{}/{}个)", 
                    node_id, index + 1, actual_concurrent);
        }
        
        // 确保节点在active_threads中标记为活跃
        {
            let mut threads_guard = active_threads.lock();
            threads_guard.insert(*node_id, true);
            if get_verbose_output() {
                log_println!("📌 节点-{}: 已在active_threads中标记为活跃", node_id);
            }
        }
        
        // 确保节点在全局活跃节点集合中
        add_global_active_node(*node_id);
        if get_verbose_output() {
            log_println!("🌍 节点-{}: 已添加到全局活跃节点集合", node_id);
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
        
        // 添加延迟，确保节点启动间隔
        if index > 0 {
            log_println!("⏱️ 节点-{}: 添加1秒启动延迟，避免同时启动过多节点", node_id);
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
        
        // 等待短暂时间，确保节点有时间启动
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    
    // 执行一次初始化同步
    sync_global_active_nodes(&active_threads, max_concurrent);
    
    (event_receiver, join_handles)
}

// 节点管理器命令枚举
#[derive(Debug)]
enum NodeManagerCommand {
    NodeStarted(u64),
    NodeStopped(u64),
    PriorityStartNode(u64),
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
    node_tx: mpsc::Sender<NodeManagerCommand>,
) {
    // 获取max_concurrent值用于节点管理
    let max_concurrent = if let Some((_, _, _, _, _, max)) = &rotation_data {
        *max
    } else {
        10 // 默认值
    };
    
    // 创建一个集合来跟踪已经处理过的停止消息，避免重复处理
    let mut processed_stop_messages = HashSet::new();
    
    // 创建一个集合来跟踪正在启动的节点，避免重复启动
    let mut starting_nodes = HashSet::new();
    
    // 创建一个新的通道，用于节点工作线程向节点管理器发送命令
    let (node_cmd_tx, mut node_cmd_rx) = mpsc::channel::<NodeManagerCommand>(100);
    
    // 定期检查和清理活动节点列表 - 更频繁执行清理
    let active_nodes_clone = active_nodes.clone();
    let active_threads_clone = active_threads.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10)); // 增加到10秒检查一次，减少频率
        loop {
            interval.tick().await;
            cleanup_active_nodes(&active_nodes_clone, &active_threads_clone, max_concurrent).await;
        }
    });
    
    // 定期执行全局节点计数同步
    let active_threads_for_sync = active_threads.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            sync_global_active_nodes(&active_threads_for_sync, max_concurrent);
        }
    });
    
    // 添加定期状态更新功能，确保活跃节点的状态显示在UI上
    if let Some(status_callback_arc_clone) = status_callback_arc.clone() {
        let active_threads_for_status = active_threads.clone();
        let global_active_nodes_clone = Arc::new(parking_lot::Mutex::new(HashSet::<u64>::new()));
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15)); // 每15秒更新一次状态
            loop {
                interval.tick().await;
                
                // 获取全局活跃节点列表
                {
                    let global_nodes = crate::prover_runtime::GLOBAL_ACTIVE_NODES.lock();
                    *global_active_nodes_clone.lock() = global_nodes.clone();
                }
                
                // 对每个全局活跃节点发送状态更新
                let active_nodes = global_active_nodes_clone.lock().clone();
                let timestamp = get_timestamp_efficient();
                
                for node_id in active_nodes {
                    // 检查节点是否真的活跃
                    let is_active = {
                        let threads_guard = active_threads_for_status.lock();
                        threads_guard.get(&node_id).copied().unwrap_or(false)
                    };
                    
                    if is_active {
                        // 发送状态更新 - 获取节点的当前具体状态
                        let node_state = get_node_state(node_id);
                        status_callback_arc_clone(node_id, format!("[{}] 节点活跃中 - {}", timestamp, node_state));
                    } else {
                        // 节点不活跃，尝试标记为活跃
                        let mut threads_guard = active_threads_for_status.lock();
                        threads_guard.insert(node_id, true);
                        
                        // 发送状态更新
                        status_callback_arc_clone(node_id, format!("[{}] 节点已恢复活跃状态", timestamp));
                    }
                }
            }
        });
    }
    
    // 添加紧急恢复监控 - 当检测到没有活跃节点时强制启动新节点
    let active_threads_for_recovery = active_threads.clone();
    let all_nodes_for_recovery = if let Some((_, _, all_nodes, _, _, _)) = &rotation_data {
        Some(all_nodes.clone())
    } else {
        None
    };
    let node_tx_for_recovery = node_tx.clone();
    let environment_for_recovery = environment.clone();
    let proxy_file_for_recovery = proxy_file.clone();
    let status_callback_arc_for_recovery = status_callback_arc.clone();
    let event_sender_for_recovery = event_sender.clone();
    let rotation_data_for_recovery = rotation_data.clone();
    let mut shutdown_for_recovery = shutdown.resubscribe(); // 确保这是可变的
    
    tokio::spawn(async move {
        // 创建一个计数器，跟踪连续检测到的无活跃节点次数
        let mut no_active_nodes_count = 0;
        let mut interval = tokio::time::interval(Duration::from_secs(30)); // 每30秒检查一次
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // 检查是否有活跃节点
                    let active_count = {
                        let threads_guard = active_threads_for_recovery.lock();
                        threads_guard.values().filter(|&&active| active).count()
                    };
                    
                    // 检查全局活跃节点数量
                    let global_active_count = get_global_active_node_count();
                    
                    // 如果本地和全局都没有活跃节点，增加计数
                    if active_count == 0 && global_active_count == 0 {
                        no_active_nodes_count += 1;
                        log_println!("⚠️ 紧急恢复监控: 没有检测到活跃节点 (连续{}次)", no_active_nodes_count);
                        
                        // 如果连续3次检测到没有活跃节点，启动紧急恢复
                        if no_active_nodes_count >= 3 {
                            log_println!("🚨 紧急恢复: 连续{}次没有检测到活跃节点，启动紧急恢复流程", no_active_nodes_count);
                            
                            // 如果有all_nodes，从中选择节点启动
                            if let Some(all_nodes) = &all_nodes_for_recovery {
                                // 选择前3个节点进行紧急启动
                                let emergency_nodes: Vec<u64> = all_nodes.iter().take(3).copied().collect();
                                
                                log_println!("🚨 紧急恢复: 将启动以下节点: {:?}", emergency_nodes);
                                
                                for &node_id in &emergency_nodes {
                                    log_println!("🚨 紧急恢复: 启动节点-{}", node_id);
                                    
                                    // 确保节点在active_threads中标记为活跃
                                    {
                                        let mut threads_guard = active_threads_for_recovery.lock();
                                        threads_guard.insert(node_id, true);
                                    }
                                    
                                    // 启动节点
                                    let handle = start_node_worker(
                                        node_id,
                                        environment_for_recovery.clone(),
                                        proxy_file_for_recovery.clone(),
                                        num_workers_per_node,
                                        proof_interval,
                                        status_callback_arc_for_recovery.clone(),
                                        event_sender_for_recovery.clone(),
                                        shutdown_for_recovery.resubscribe(),
                                        rotation_data_for_recovery.clone(),
                                        active_threads_for_recovery.clone(),
                                        node_tx_for_recovery.clone(),
                                    ).await;
                                    
                                    // 不需要存储句柄，因为它们会在完成时自动清理
                                    tokio::spawn(async move {
                                        let _ = handle.await;
                                    });
                                    
                                    // 等待一段时间，避免同时启动多个节点
                                    tokio::time::sleep(Duration::from_secs(2)).await;
                                }
                                
                                // 重置计数器
                                no_active_nodes_count = 0;
                            } else {
                                log_println!("🚨 紧急恢复: 没有可用的节点列表，无法启动紧急恢复");
                            }
                        }
                    } else {
                        // 如果有活跃节点，重置计数器
                        if no_active_nodes_count > 0 {
                            log_println!("✅ 紧急恢复监控: 检测到活跃节点，重置计数器 (本地: {}, 全局: {})", 
                                    active_count, global_active_count);
                            no_active_nodes_count = 0;
                        }
                    }
                }
                _ = shutdown_for_recovery.recv() => {
                    log_println!("🛑 紧急恢复监控: 收到关闭信号，正在停止");
                    break;
                }
            }
        }
    });
    
    // 记录上次检查时间，避免频繁检查
    let mut last_check_time = Instant::now();
    let check_interval = Duration::from_secs(5); // 每5秒检查一次
    
    loop {
        tokio::select! {
            // 处理关闭信号
            _ = shutdown.recv() => {
                log_println!("🛑 节点管理器: 收到关闭信号，停止所有节点");
                break;
            }
            
            // 处理原始节点命令通道
            Some(cmd) = node_rx.recv() => {
                match &cmd {
                    NodeManagerCommand::PriorityStartNode(node_id) => {
                        log_println!("🚀 节点管理器: 收到优先启动节点-{} 的命令", node_id);
                        
                        // 直接调用处理函数
                        handle_node_command(cmd, &mut processed_stop_messages, &mut starting_nodes, 
                                          &active_nodes, &active_threads, &environment, &proxy_file, 
                                          num_workers_per_node, proof_interval, &status_callback_arc, 
                                          &event_sender, &shutdown, &node_cmd_tx, &rotation_data, max_concurrent).await;
                    },
                    _ => {
                        // 对于其他命令，使用原有的处理方式
                        handle_node_command(cmd, &mut processed_stop_messages, &mut starting_nodes, 
                                          &active_nodes, &active_threads, &environment, &proxy_file, 
                                          num_workers_per_node, proof_interval, &status_callback_arc, 
                                          &event_sender, &shutdown, &node_cmd_tx, &rotation_data, max_concurrent).await;
                    }
                }
            }
            
            // 处理新创建的节点命令通道
            Some(cmd) = node_cmd_rx.recv() => {
                match &cmd {
                    NodeManagerCommand::PriorityStartNode(node_id) => {
                        log_println!("🚀 节点管理器: 收到优先启动节点-{} 的命令 (内部通道)", node_id);
                        
                        // 直接调用处理函数
                        handle_node_command(cmd, &mut processed_stop_messages, &mut starting_nodes, 
                                          &active_nodes, &active_threads, &environment, &proxy_file, 
                                          num_workers_per_node, proof_interval, &status_callback_arc, 
                                          &event_sender, &shutdown, &node_cmd_tx, &rotation_data, max_concurrent).await;
                    },
                    _ => {
                        // 对于其他命令，使用原有的处理方式
                        handle_node_command(cmd, &mut processed_stop_messages, &mut starting_nodes, 
                                          &active_nodes, &active_threads, &environment, &proxy_file, 
                                          num_workers_per_node, proof_interval, &status_callback_arc, 
                                          &event_sender, &shutdown, &node_cmd_tx, &rotation_data, max_concurrent).await;
                    }
                }
            }
            
            // 定期检查是否有节点需要启动 - 更短的检查间隔
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // 检查是否到了检查时间
                if last_check_time.elapsed() < check_interval {
                    continue;
                }
                
                // 更新上次检查时间
                last_check_time = Instant::now();
                
                // 每次检查前强制执行清理，确保活动节点列表和活动线程状态一致
                cleanup_active_nodes(&active_nodes, &active_threads, max_concurrent).await;
                
                // 获取全局活跃节点数量
                let global_active_count = get_global_active_node_count();
                
                // 确认清理后的状态
                let current_active_count = {
                    let threads_guard = active_threads.lock();
                    threads_guard.values().filter(|&&active| active).count()
                };
                
                let active_nodes_count = {
                    let nodes_guard = active_nodes.lock();
                    nodes_guard.len()
                };
                
                if get_verbose_output() {
                    log_println!("📊 节点管理器: 定期检查 - 当前活动节点数量: {}, 活动列表长度: {}, 全局活跃数量: {}, 最大并发数: {}", 
                            current_active_count, active_nodes_count, global_active_count, max_concurrent);
                }
                
                // 如果活动节点数量或活动列表长度超过最大并发数，执行强制清理
                if current_active_count > max_concurrent || active_nodes_count > max_concurrent || global_active_count > max_concurrent {
                    log_println!("⚠️ 节点管理器: 状态不一致或超出限制，执行强制清理");
                    
                    // 强制同步全局活跃节点集合
                    sync_global_active_nodes(&active_threads, max_concurrent);
                    
                    // 然后清理活动节点列表
                    cleanup_active_nodes(&active_nodes, &active_threads, max_concurrent).await;
                }
                
                // 获取需要启动的节点
                let nodes_to_start = get_nodes_to_start(&active_nodes, &active_threads).await;
                
                // 获取最新的全局活跃节点数量
                let global_active_count = get_global_active_node_count();
                
                // 确认最终状态
                let final_active_count = {
                    let threads_guard = active_threads.lock();
                    let active_count = threads_guard.values().filter(|&&active| active).count();
                    
                    // 减少输出，只显示总数
                    if get_verbose_output() {
                        log_println!("🔍 节点状态检查: 总节点数: {}, 活跃节点数: {}", threads_guard.len(), active_count);
                    }
                    
                    active_count
                };
                
                // 使用全局计数和本地计数的较大值来计算可用槽位，确保更严格的控制
                let effective_active_count = std::cmp::max(global_active_count, final_active_count);
                
                // 计算可以启动的节点数量
                let available_slots = if effective_active_count < max_concurrent {
                    max_concurrent - effective_active_count
                } else {
                    0
                };
                
                // 检查是否有节点被标记为需要启动但尚未启动（扫描 active_threads 中标记为 false 的节点）
                let nodes_needing_start = {
                    let threads_guard = active_threads.lock();
                    let mut nodes: Vec<u64> = Vec::new();
                    for (&node_id, &is_active) in threads_guard.iter() {
                        if !is_active && !starting_nodes.contains(&node_id) {
                            nodes.push(node_id);
                        }
                    }
                    nodes
                };
                
                // 如果有节点需要启动，优先启动这些节点
                if !nodes_needing_start.is_empty() && available_slots > 0 {
                    log_println!("🚀 节点管理器: 发现 {} 个节点需要启动，有 {} 个可用槽位", 
                            nodes_needing_start.len(), available_slots);
                    
                    // 只启动可用槽位数量的节点
                    let nodes_to_launch = nodes_needing_start.into_iter()
                        .filter(|&node_id| !starting_nodes.contains(&node_id) && !is_node_globally_active(node_id))
                        .take(available_slots)
                        .collect::<Vec<_>>();
                    
                    if !nodes_to_launch.is_empty() {
                        log_println!("🚀 节点管理器: 准备启动 {} 个标记为需要启动的节点", nodes_to_launch.len());
                        
                        // 标记这些节点为正在启动
                        for &node_id in &nodes_to_launch {
                            starting_nodes.insert(node_id);
                            log_println!("🚀 节点管理器: 节点-{} 标记为正在启动", node_id);
                        }
                        
                        // 启动节点
                        for node_id in nodes_to_launch {
                            // 再次确认全局活跃节点数量未超限
                            if get_global_active_node_count() >= max_concurrent {
                                log_println!("⚠️ 节点管理器: 全局活跃节点数量已达到最大并发数，取消启动剩余节点");
                                break;
                            }
                            
                            // 启动新节点
                            log_println!("🚀 节点管理器: 启动节点-{}", node_id);
                            
                            // 确保节点在active_threads中标记为活跃
                            {
                                let mut threads_guard = active_threads.lock();
                                threads_guard.insert(node_id, true);
                            }
                            
                            // 确保节点在全局活跃节点集合中
                            add_global_active_node(node_id);
                            
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
                                node_cmd_tx.clone(), // 使用克隆的通信通道
                            ).await;
                            
                            // 不需要存储句柄，因为它们会在完成时自动清理
                            tokio::spawn(async move {
                                let _ = handle.await;
                            });
                            
                            // 短暂等待确保节点启动逻辑完成
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    }
                }
                // 如果没有节点需要启动，但有可用槽位和待启动节点，则启动这些节点
                else if available_slots > 0 && !nodes_to_start.is_empty() {
                    log_println!("📊 节点管理器: 有 {} 个可用槽位，可以启动新节点", available_slots);
                    
                    // 只启动可用槽位数量的节点（限定为active_nodes中的待启动节点）
                    let nodes_to_start = nodes_to_start.into_iter()
                        .filter(|&node_id| !starting_nodes.contains(&node_id) && !is_node_globally_active(node_id))
                        .take(available_slots)
                        .collect::<Vec<_>>();
                    
                    if !nodes_to_start.is_empty() {
                        log_println!("🚀 节点管理器: 准备启动 {} 个新节点", nodes_to_start.len());
                        
                        // 标记这些节点为正在启动
                        for &node_id in &nodes_to_start {
                            starting_nodes.insert(node_id);
                        }
                        
                        // 启动节点
                        for node_id in nodes_to_start {
                            // 再次确认全局活跃节点数量未超限
                            if get_global_active_node_count() >= max_concurrent {
                                log_println!("⚠️ 节点管理器: 全局活跃节点数量已达到最大并发数，取消启动剩余节点");
                                break;
                            }
                            
                            // 启动新节点
                            log_println!("🚀 节点管理器: 启动节点-{}", node_id);
                            
                            // 确保节点在active_threads中标记为活跃
                            {
                                let mut threads_guard = active_threads.lock();
                                threads_guard.insert(node_id, true);
                            }
                            
                            // 确保节点在全局活跃节点集合中
                            add_global_active_node(node_id);
                            
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
                                node_cmd_tx.clone(),
                            ).await;
                            
                            // 不需要存储句柄，因为它们会在完成时自动清理
                            tokio::spawn(async move {
                                let _ = handle.await;
                            });
                            
                            // 短暂等待确保节点启动逻辑完成
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    }
                }
                else if current_active_count == 0 && global_active_count == 0 {
                    log_println!("⚠️ 节点管理器: 没有活跃节点，尝试紧急启动");
                    
                    // 从活动节点列表中选择一个节点启动
                    let emergency_node_opt = {
                        let nodes_guard = active_nodes.lock();
                        nodes_guard.first().copied()
                    };
                    
                    if let Some(node_id) = emergency_node_opt {
                        log_println!("🚨 紧急启动: 选择节点-{}", node_id);
                        
                        // 确保节点在active_threads中标记为活跃
                        {
                            let mut threads_guard = active_threads.lock();
                            threads_guard.insert(node_id, true);
                        }
                        
                        // 确保节点在全局活跃节点集合中
                        add_global_active_node(node_id);
                        
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
                            node_cmd_tx.clone(),
                        ).await;
                        
                        // 不需要存储句柄，因为它们会在完成时自动清理
                        tokio::spawn(async move {
                            let _ = handle.await;
                        });
                    }
                }
            }
        }
    }
}

// 提取处理节点命令的逻辑为一个单独的函数
async fn handle_node_command(
    cmd: NodeManagerCommand,
    processed_stop_messages: &mut HashSet<u64>,
    starting_nodes: &mut HashSet<u64>,
    active_nodes: &Arc<Mutex<Vec<u64>>>,
    active_threads: &Arc<Mutex<HashMap<u64, bool>>>,
    environment: &Environment,
    proxy_file: &Option<String>,
    num_workers_per_node: usize,
    proof_interval: u64,
    status_callback_arc: &Option<Arc<Box<dyn Fn(u64, String) + Send + Sync + 'static>>>,
    event_sender: &mpsc::Sender<Event>,
    shutdown: &broadcast::Receiver<()>,
    node_cmd_tx: &mpsc::Sender<NodeManagerCommand>,
    rotation_data: &Option<(Arc<Mutex<Vec<u64>>>, Arc<AtomicU64>, Arc<Vec<u64>>, Arc<std::sync::atomic::AtomicBool>, Arc<Mutex<HashMap<u64, usize>>>, usize)>,
    max_concurrent: usize,
) {
    match cmd {
        NodeManagerCommand::NodeStarted(node_id) => {
            // 节点已启动，从启动中列表移除
            starting_nodes.remove(&node_id);
        }
        NodeManagerCommand::NodeStopped(node_id) => {
            // 检查是否已经处理过这个停止消息
            if processed_stop_messages.contains(&node_id) {
                return;
            }
            
            // 标记为已处理
            processed_stop_messages.insert(node_id);
            
            // 在一段时间后移除已处理标记，允许将来再次处理该节点的停止消息
            let node_id_clone = node_id;
            let processed_messages_clone = Arc::new(Mutex::new(processed_stop_messages.clone()));
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let mut guard = processed_messages_clone.lock();
                guard.remove(&node_id_clone);
            });
            
            log_println!("🛑 节点管理器: 节点-{} 已停止", node_id);
            
            // 更新节点状态
            {
                let mut threads_guard = active_threads.lock();
                threads_guard.insert(node_id, false);
            }
            
            log_println!("🔄 节点管理器: 节点-{} 已停止，准备启动新节点", node_id);
            
            // 获取需要启动的节点
            let nodes_to_start = get_nodes_to_start(active_nodes, active_threads).await;
            
            // 确保不超过最大并发数
            let current_active_count = {
                let threads_guard = active_threads.lock();
                threads_guard.values().filter(|&&active| active).count()
            };
            
            // 计算可以启动的节点数量
            let available_slots = if current_active_count < max_concurrent {
                max_concurrent - current_active_count
            } else {
                0
            };
            
            if available_slots > 0 {
                // 只启动可用槽位数量的节点
                let nodes_to_start = nodes_to_start.into_iter()
                    .filter(|&node_id| !starting_nodes.contains(&node_id))
                    .take(available_slots)
                    .collect::<Vec<_>>();
                
                // 标记这些节点为正在启动
                for &node_id in &nodes_to_start {
                    starting_nodes.insert(node_id);
                }
                
                // 启动节点
                for node_id in nodes_to_start {
                    // 启动新节点
                    log_println!("🚀 节点管理器: 启动节点-{}", node_id);
                    
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
                        node_cmd_tx.clone(),
                    ).await;
                    
                    // 不需要存储句柄，因为它们会在完成时自动清理
                    tokio::spawn(async move {
                        let _ = handle.await;
                    });
                }
            } else {
                if get_verbose_output() {
                    log_println!("⚠️ 节点管理器: 已达到最大并发数 {}, 暂不启动新节点", max_concurrent);
                }
            }
        }
        NodeManagerCommand::PriorityStartNode(node_id) => {
            log_println!("🚀 节点管理器: 收到优先启动节点-{} 的命令", node_id);
            
            // 如果节点已经在启动中，不重复启动
            if starting_nodes.contains(&node_id) {
                log_println!("⚠️ 节点管理器: 节点-{} 已在启动中，跳过", node_id);
                return;
            }
            
            // 如果节点已经活跃，不重复启动
            let is_active = {
                let threads_guard = active_threads.lock();
                threads_guard.get(&node_id).copied().unwrap_or(false)
            };
            
            if is_active {
                log_println!("⚠️ 节点管理器: 节点-{} 已经活跃，跳过启动", node_id);
                return;
            }
            
            // 标记为正在启动
            starting_nodes.insert(node_id);
            
            // 确保节点在active_threads中标记为活跃
            {
                let mut threads_guard = active_threads.lock();
                threads_guard.insert(node_id, true);
                log_println!("📌 节点-{}: 已在active_threads中标记为活跃", node_id);
            }
            
            // 确保节点在全局活跃节点集合中
            add_global_active_node(node_id);
            log_println!("🌍 节点-{}: 已添加到全局活跃节点集合", node_id);
            
            // 确保节点在活动节点列表中
            {
                let mut active_nodes_guard = active_nodes.lock();
                if !active_nodes_guard.contains(&node_id) && active_nodes_guard.len() < max_concurrent {
                    active_nodes_guard.push(node_id);
                    log_println!("📋 节点-{}: 已添加到活动节点列表", node_id);
                }
            }
            
            // 检查内存压力，如果需要则等待更长时间
            let defragmenter = get_defragmenter();
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
            
            log_println!("🚀 节点管理器: 正在启动优先节点-{}", node_id);
            
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
                node_cmd_tx.clone(),
            ).await;
            
            // 不需要存储句柄，因为它们会在完成时自动清理
            tokio::spawn(async move {
                let _ = handle.await;
            });
            
            // 等待短暂时间，确保节点有时间启动
            tokio::time::sleep(Duration::from_millis(500)).await;
            
            // 从启动中列表移除
            starting_nodes.remove(&node_id);
            log_println!("✅ 节点管理器: 已启动优先节点-{}", node_id);
        }
    }
}

// 获取需要启动的节点列表
async fn get_nodes_to_start(
    active_nodes: &Arc<Mutex<Vec<u64>>>,
    active_threads: &Arc<Mutex<HashMap<u64, bool>>>,
) -> Vec<u64> {
    // 获取需要启动的节点列表和活动节点数量
    let to_start;
    let active_count;
    let global_active_count = get_global_active_node_count();
    
    // 使用作用域确保锁在操作完成后释放
    {
        let active_nodes_guard = active_nodes.lock();
        let active_threads_guard = active_threads.lock();
        
        // 减少输出，只显示关键信息
        let active_node_count = active_nodes_guard.len();
        let active_thread_count = active_threads_guard.values().filter(|&&active| active).count();
        
        if get_verbose_output() {
            log_println!("\n🔍 get_nodes_to_start: 活动节点列表大小: {}, 活跃线程数: {}, 全局活跃: {}", 
                    active_node_count, active_thread_count, global_active_count);
        }
        
        // 检查每个活动节点，找出没有运行的节点
        to_start = active_nodes_guard.iter()
            .filter(|&&node_id| {
                let is_active = active_threads_guard.get(&node_id).copied().unwrap_or(false);
                // 只在详细模式下输出单个节点状态
                if !is_active && get_verbose_output() {
                    log_println!("  - 节点-{}: 未在active_threads中标记为活跃，需要启动", node_id);
                }
                !is_active
            })
            .copied()
            .collect::<Vec<u64>>();
        
        // 计算当前活动节点数量
        active_count = active_threads_guard.iter()
            .filter(|pair| *pair.1)
            .count();
    }
    
    // 减少输出，只显示关键信息
    if to_start.len() > 0 {
        log_println!("🔍 需要启动 {} 个节点, 当前活跃节点数: {}, 全局活跃节点数: {}", 
                to_start.len(), active_count, global_active_count);
    }
    
    // 只在详细模式下显示完整节点列表
    if get_verbose_output() {
        log_println!("🔄 节点列表: {:?}", to_start);
    } else if to_start.len() <= 5 && to_start.len() > 0 {
        // 非详细模式下，如果节点数量较少，仍然显示节点列表
        log_println!("🔄 节点列表: {:?}", to_start);
    }
    
    log_println!("🔄 节点管理器: 当前活动节点数量: {}, 全局活跃节点数量: {}", active_count, global_active_count);
    
    // 如果没有找到需要启动的节点，但活动节点列表不为空且活动节点数量为0，
    // 尝试从活动节点列表中获取一个节点来启动
    if to_start.is_empty() && active_count == 0 {
        let mut emergency_nodes = Vec::new();
        
        // 获取活动节点列表
        let active_nodes_list = {
            let active_nodes_guard = active_nodes.lock();
            active_nodes_guard.clone()
        };
        
        if !active_nodes_list.is_empty() {
            // 选择第一个节点作为紧急启动节点
            let emergency_node = active_nodes_list[0];
            emergency_nodes.push(emergency_node);
            
            log_println!("⚠️ 节点管理器: 紧急情况 - 没有活跃节点，选择节点-{} 进行紧急启动", emergency_node);
            
            // 确保这个节点在active_threads中标记为非活跃
            {
                let mut threads_guard = active_threads.lock();
                threads_guard.insert(emergency_node, false);
            }
            
            return emergency_nodes;
        }
    }
    
    to_start
}

// 轮转到下一个节点的函数
async fn rotate_to_next_node(
    node_id: u64,
    rotation_data: &Option<(Arc<Mutex<Vec<u64>>>, Arc<AtomicU64>, Arc<Vec<u64>>, Arc<std::sync::atomic::AtomicBool>, Arc<Mutex<HashMap<u64, usize>>>, usize)>,
    reason: &str,
    node_tx: &mpsc::Sender<NodeManagerCommand>,
    active_threads: &Arc<Mutex<HashMap<u64, bool>>>,
) -> (bool, Option<String>) {
    if get_verbose_output() {
        log_println!("\n📣 节点-{}: 尝试轮转 (原因: {})", node_id, reason);
    }
    
    // 从全局活跃节点集合移除当前节点
    remove_global_active_node(node_id);
    if get_verbose_output() {
        log_println!("🌍 节点-{}: 已从全局活跃节点集合移除", node_id);
    }
    
    if let Some((active_nodes, _next_node_index, all_nodes, all_nodes_started, node_indices, max_concurrent)) = rotation_data {
        // 检查所有初始节点是否已启动
        if !all_nodes_started.load(std::sync::atomic::Ordering::SeqCst) {
            log_println!("⚠️ 节点-{}: 所有初始节点尚未启动完成，暂不轮转", node_id);
            return (false, Some(format!("⚠️ 节点-{}: 所有初始节点尚未启动完成，暂不轮转", node_id)));
        }
        
        // 确保当前节点在active_threads中标记为活跃，避免不一致状态
        {
            let mut threads_guard = active_threads.lock();
            if !threads_guard.get(&node_id).copied().unwrap_or(false) {
                log_println!("⚠️ 节点-{}: 在active_threads中未标记为活跃，正在修复", node_id);
                threads_guard.insert(node_id, true);
            }
        }
        
        // 获取当前活跃节点数量（仅用于日志记录）
        let current_active_count = {
            let threads_guard = GLOBAL_ACTIVE_NODES.lock();
            threads_guard.len()
        };
        
        log_println!("📊 节点-{}: 当前活跃节点数量: {}/{}", node_id, current_active_count, *max_concurrent);
        
        // 获取当前节点的索引
        let node_idx_opt = {
            let node_indices_guard = node_indices.lock();
            node_indices_guard.get(&node_id).copied()
        };
        
        if let Some(node_idx) = node_idx_opt {
            // 计算下一个节点的索引：当前索引 + max_concurrent，以确保节点分散
            let jump_distance = *max_concurrent;
            let next_idx = (node_idx + jump_distance) % all_nodes.len();
            let next_node_id = all_nodes[next_idx];
            
            // 确保不会轮转到自己
            let final_next_idx = if next_node_id == node_id && all_nodes.len() > 1 {
                // 如果轮转到自己且有其他节点可用，则选择下一个节点
                let alternative_idx = (next_idx + 1) % all_nodes.len();
                log_println!("⚠️ 节点-{}: 避免轮转到自己，改为使用索引 {}", node_id, alternative_idx);
                alternative_idx
            } else {
                next_idx
            };
            
            let final_next_node_id = all_nodes[final_next_idx];
            
            log_println!("📊 节点-{}: 当前索引: {}, 下一个索引: {}, 总节点数: {}", 
                    node_id, node_idx, final_next_idx, all_nodes.len());
            log_println!("🔄 节点-{}: 将轮转到节点-{} (索引: {})", node_id, final_next_node_id, final_next_idx);
            
            // 检查新节点是否已经在全局活跃节点集合中
            if is_node_globally_active(final_next_node_id) {
                log_println!("⚠️ 节点-{}: 新节点-{} 已经在全局活跃节点集合中，不重复添加", 
                        node_id, final_next_node_id);
                
                // 通知节点管理器当前节点已停止
                let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                
                return (true, Some(format!("⚠️ 节点-{}: 新节点-{} 已在全局活跃节点集合中，跳过添加", 
                                       node_id, final_next_node_id)));
            }
            
            // 获取当前活跃节点列表并打印（在一个独立的作用域内）
            {
                let active_nodes_guard = active_nodes.lock();
                log_println!("📋 节点-{}: 轮转前活动节点列表: {:?}", node_id, *active_nodes_guard);
                log_println!("📋 节点-{}: 活动节点数量: {}, 最大并发数: {}", node_id, active_nodes_guard.len(), *max_concurrent);
                // 锁在这里释放
            }
            
            // 执行所有不需要await的操作，捕获结果
            let result = {
                let mut active_nodes_guard = active_nodes.lock();
                
                // 查找当前节点在活动列表中的位置
                let pos = active_nodes_guard.iter().position(|&id| id == node_id);
                
                if let Some(pos) = pos {
                    // 当前节点在列表中，直接替换
                    log_println!("✅ 节点-{}: 在活动列表中找到位置 {}", node_id, pos);
                    active_nodes_guard[pos] = final_next_node_id;
                    log_println!("✅ 节点-{}: 已替换为节点-{}", node_id, final_next_node_id);
                    
                    // 确保当前节点已从全局活跃节点集合中移除
                    remove_global_active_node(node_id);
                    log_println!("🌍 节点-{}: 已从全局活跃节点集合中移除", node_id);
                    
                    // 将新节点添加到全局活跃节点集合
                    add_global_active_node(final_next_node_id);
                    log_println!("🌍 节点-{}: 新节点-{} 已添加到全局活跃节点集合", node_id, final_next_node_id);
                    
                    // 创建一个任务来启动新节点
                    log_println!("🚀 节点-{}: 正在触发新节点-{} 的启动", node_id, final_next_node_id);

                    // 同时更新active_threads映射
                    {
                        let mut threads_guard = active_threads.lock();
                        // 将当前节点标记为非活跃
                        threads_guard.insert(node_id, false);
                        // 将新节点标记为活跃
                        threads_guard.insert(final_next_node_id, true);
                        log_println!("📊 节点-{}: 已在active_threads中将节点-{} 标记为非活跃，将节点-{} 标记为活跃", 
                                node_id, node_id, final_next_node_id);
                    }
                    
                    // 最后再次确保活动节点列表不超过最大并发数
                    if active_nodes_guard.len() > *max_concurrent {
                        log_println!("⚠️ 节点-{}: 轮转后强制检查 - 活动节点列表超出限制 ({} > {}), 进行截断", 
                                node_id, active_nodes_guard.len(), *max_concurrent);
                        active_nodes_guard.truncate(*max_concurrent);
                        log_println!("✅ 节点-{}: 已强制截断活动节点列表至 {} 个节点", node_id, active_nodes_guard.len());
                    }
                    
                    // 返回成功结果
                    Ok(final_next_node_id)
                } else {
                    // 当前节点不在列表中
                    log_println!("\n⚠️ 节点-{}: 未在活动列表中找到", node_id);
                    
                    // 如果列表未满，尝试添加新节点
                    if active_nodes_guard.len() < *max_concurrent {
                        active_nodes_guard.push(final_next_node_id);
                        log_println!("✅ 节点-{}: 已添加新节点-{} 到活动列表", node_id, final_next_node_id);
                        
                        // 将新节点添加到全局活跃节点集合
                        add_global_active_node(final_next_node_id);
                        log_println!("🌍 节点-{}: 新节点-{} 已添加到全局活跃节点集合", node_id, final_next_node_id);
                        
                        // 同时更新active_threads映射
                        {
                            let mut threads_guard = active_threads.lock();
                            // 将当前节点标记为非活跃
                            threads_guard.insert(node_id, false);
                            // 将新节点标记为活跃
                            threads_guard.insert(final_next_node_id, true);
                            log_println!("📊 节点-{}: 已在active_threads中将节点-{} 标记为非活跃，将节点-{} 标记为活跃", 
                                    node_id, node_id, final_next_node_id);
                        }
                        
                        // 最后再次确保活动节点列表不超过最大并发数
                        if active_nodes_guard.len() > *max_concurrent {
                            log_println!("⚠️ 节点-{}: 轮转后强制检查 - 活动节点列表超出限制 ({} > {}), 进行截断", 
                                    node_id, active_nodes_guard.len(), *max_concurrent);
                            active_nodes_guard.truncate(*max_concurrent);
                            log_println!("✅ 节点-{}: 已强制截断活动节点列表至 {} 个节点", node_id, active_nodes_guard.len());
                        }
                        
                        // 返回成功结果
                        Ok(final_next_node_id)
                    } else {
                        // 列表已满，尝试替换一个节点
                        log_println!("⚠️ 节点-{}: 活动节点数量已达到最大并发数 {}, 尝试替换一个节点", node_id, *max_concurrent);
                        
                        // 选择第一个节点进行替换
                        if !active_nodes_guard.is_empty() {
                            let replaced_node = active_nodes_guard[0];
                            active_nodes_guard[0] = final_next_node_id;
                            log_println!("✅ 节点-{}: 已替换节点-{} 为节点-{}", node_id, replaced_node, final_next_node_id);
                            
                            // 从全局活跃节点集合中移除被替换的节点
                            remove_global_active_node(replaced_node);
                            
                            // 将新节点添加到全局活跃节点集合
                            add_global_active_node(final_next_node_id);
                            log_println!("🌍 节点-{}: 新节点-{} 已添加到全局活跃节点集合", node_id, final_next_node_id);
                            
                            // 同时更新active_threads映射
                            {
                                let mut threads_guard = active_threads.lock();
                                // 将当前节点和被替换的节点标记为非活跃
                                threads_guard.insert(node_id, false);
                                threads_guard.insert(replaced_node, false);
                                // 将新节点标记为活跃
                                threads_guard.insert(final_next_node_id, true);
                                log_println!("📊 节点-{}: 已在active_threads中将节点-{} 和节点-{} 标记为非活跃，将节点-{} 标记为活跃", 
                                        node_id, node_id, replaced_node, final_next_node_id);
                            }
                            
                            // 最后再次确保活动节点列表不超过最大并发数
                            if active_nodes_guard.len() > *max_concurrent {
                                log_println!("⚠️ 节点-{}: 轮转后强制检查 - 活动节点列表超出限制 ({} > {}), 进行截断", 
                                        node_id, active_nodes_guard.len(), *max_concurrent);
                                active_nodes_guard.truncate(*max_concurrent);
                                log_println!("✅ 节点-{}: 已强制截断活动节点列表至 {} 个节点", node_id, active_nodes_guard.len());
                            }
                            
                            // 返回成功结果
                            Ok(final_next_node_id)
                        } else {
                            log_println!("❌ 节点-{}: 活动节点列表为空，无法替换", node_id);
                            Err("活动节点列表为空，无法替换")
                        }
                    }
                }
            }; // 锁在这里释放
            
            // 处理结果，如果成功则继续处理
            let final_next_node_id = match result {
                Ok(id) => id,
                Err(e) => {
                    return (false, Some(format!("❌ 节点-{}: {}", node_id, e)));
                }
            };
            
            // 所有锁释放后再发送命令
            let _ = node_tx.send(NodeManagerCommand::PriorityStartNode(final_next_node_id)).await;
            log_println!("🚀 节点-{}: 已发送优先启动命令给节点管理器，启动节点-{}", node_id, final_next_node_id);
            
            // 通知节点管理器当前节点已停止
            log_println!("📣 节点-{}: 正在通知节点管理器节点停止", node_id);
            
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
                        log_println!("📣 节点-{}: 已成功通知节点管理器节点停止", node_id);
                        // 成功发送消息，直接退出循环
                        break;
                    },
                    Ok(Err(e)) => {
                        retry_count += 1;
                        log_println!("⚠️ 节点-{}: 通知节点管理器失败 (尝试 {}/{}): {}", node_id, retry_count, max_retries, e);
                        
                        if retry_count >= max_retries {
                            log_println!("⚠️ 节点-{}: 通知节点管理器失败，达到最大重试次数", node_id);
                        } else {
                            // 短暂等待后重试
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    },
                    Err(_) => {
                        retry_count += 1;
                        log_println!("⚠️ 节点-{}: 通知节点管理器超时 (尝试 {}/{})", node_id, retry_count, max_retries);
                        
                        if retry_count >= max_retries {
                            log_println!("⚠️ 节点-{}: 通知节点管理器超时，达到最大重试次数", node_id);
                        } else {
                            // 短暂等待后重试
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    },
                }
            }
            
            // 创建一个临时的活动线程状态映射，用于清理
            let active_threads_for_cleanup = Arc::new(Mutex::new(HashMap::<u64, bool>::new()));
            
            // 将新节点标记为活跃状态
            {
                let mut threads_guard = active_threads_for_cleanup.lock();
                threads_guard.insert(final_next_node_id, true);
            }
            
            // 强制执行一次节点清理，确保状态一致
            cleanup_active_nodes(active_nodes, &active_threads_for_cleanup, *max_concurrent).await;
            
            // 确保新节点在全局活跃节点集合中
            if !is_node_globally_active(final_next_node_id) {
                add_global_active_node(final_next_node_id);
                log_println!("🌍 节点-{}: 确保新节点-{} 在全局活跃节点集合中", node_id, final_next_node_id);
            }
            
            // 生成状态消息
            let status_msg = format!("🔄 节点轮转: {} → {} (原因: {}) - 当前节点已处理完毕", node_id, final_next_node_id, reason);
            
            log_println!("\n{}\n", status_msg); // 添加明显的控制台输出
            
            // 等待一小段时间，确保节点管理器有时间处理消息
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            
            return (true, Some(status_msg));
        } else {
            log_println!("⚠️ 节点-{}: 未找到节点索引，无法轮转", node_id);
            return (false, None);
        }
    } else {
        // 轮转功能未启用
        log_println!("\n⚠️ 节点-{}: 轮转功能未启用或配置错误，无法轮转 (原因: {})\n", node_id, reason);
    }
    log_println!("❌ 节点-{}: 轮转失败", node_id);
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
    // 获取最大并发数
    let max_concurrent = if let Some((_, _, _, _, _, max)) = &rotation_data {
        *max
    } else {
        10 // 默认值
    };

    // 输出节点启动详细日志
    log_println!("\n🚀 开始启动节点-{} (最大并发: {})", node_id, max_concurrent);

    // 全局并发检查 - 如果已达到最大并发数且该节点不在活跃列表中，则不启动
    let global_active_count = get_global_active_node_count();
    if global_active_count >= max_concurrent && !is_node_globally_active(node_id) {
        log_println!("⚠️ 节点-{}: 全局活跃节点数量 ({}) 已达到最大并发数 ({}), 拒绝启动", 
                node_id, global_active_count, max_concurrent);
                
        // 使用Arc包装的回调
        if let Some(callback_arc) = &status_callback_arc {
            callback_arc(node_id, format!("拒绝启动: 已达到最大并发数 {}", max_concurrent));
        }
        
        // 返回一个已完成的JoinHandle
        return tokio::spawn(async move {
            log_println!("🛑 节点-{}: 启动被拒绝，返回空任务", node_id);
        });
    }

    log_println!("✅ 节点-{}: 并发检查通过，当前活跃节点: {}/{}", node_id, global_active_count, max_concurrent);

    // 获取密钥
    log_println!("🔑 节点-{}: 正在加载密钥...", node_id);
    let signing_key = match crate::key_manager::load_or_generate_signing_key() {
        Ok(key) => {
            log_println!("✅ 节点-{}: 密钥加载成功", node_id);
            key
        },
        Err(e) => {
            log_println!("❌ 节点-{}: 密钥加载失败: {}", node_id, e);
            warn!("节点-{} 加载签名密钥失败: {}", node_id, e);
            // 使用Arc包装的回调
            if let Some(callback_arc) = &status_callback_arc {
                callback_arc(node_id, format!("加载密钥失败: {}", e));
            }
            
            // 返回一个已完成的JoinHandle
            return tokio::spawn(async {});
        }
    };
    
    // 使用增强版客户端
    log_println!("🌐 节点-{}: 创建客户端...", node_id);
    let enhanced_orchestrator = if let Some(ref proxy_file) = proxy_file {
        log_println!("🌐 节点-{}: 使用代理文件: {}", node_id, proxy_file);
        EnhancedOrchestratorClient::new_with_proxy(environment.clone(), Some(proxy_file.as_str()))
    } else {
        log_println!("🌐 节点-{}: 不使用代理", node_id);
        EnhancedOrchestratorClient::new(environment.clone())
    };
    
    let client_id = format!("{:x}", md5::compute(node_id.to_le_bytes()));
    log_println!("🔑 节点-{}: 客户端ID: {}", node_id, client_id);

    // 先发送节点启动通知
    log_println!("📣 节点-{}: 发送启动通知到节点管理器", node_id);
    let node_tx_for_notify = node_tx.clone();
    let notify_future = node_tx_for_notify.send(NodeManagerCommand::NodeStarted(node_id));
    
    // 等待通知完成
    match tokio::time::timeout(Duration::from_secs(2), notify_future).await {
        Ok(Ok(_)) => log_println!("📣 节点-{}: 已成功通知节点管理器节点启动", node_id),
        Ok(Err(e)) => log_println!("⚠️ 节点-{}: 通知节点管理器启动失败: {}", node_id, e),
        Err(_) => log_println!("⚠️ 节点-{}: 通知节点管理器启动超时", node_id),
    }
    
    // 立即发送一次初始状态更新，确保节点在UI上显示
    log_println!("📱 节点-{}: 发送初始状态更新到UI", node_id);
    if let Some(callback_arc) = &status_callback_arc {
        callback_arc(node_id, format!("🚀 节点已启动，准备获取任务"));
    }
    
    // 预先设置节点状态，而不是在tokio::spawn内部
    {
        let mut threads_guard = active_threads.lock();
        threads_guard.insert(node_id, true);
        log_println!("📌 节点-{}: 预先设置为活跃", node_id);
    }
    
    // 确保节点在全局活跃节点集合中
    add_global_active_node(node_id);
    log_println!("🌍 节点-{}: 已添加到全局活跃节点集合", node_id);
    
    // 准备要传递给新线程的值，必须是Send + 'static
    // 为了避免传递active_threads_clone但实际上是在新线程中await之前使用它，
    // 我们显式地创建一个新的Arc<Mutex<HashMap>>

    // 复制需要的回调函数
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
    
    // 为新线程准备所需变量
    let event_sender_clone = event_sender.clone();
    let node_tx_clone = node_tx.clone();
    
    // 创建一个完全独立的活动线程状态映射
    let active_threads_safe = Arc::new(parking_lot::Mutex::new(HashMap::<u64, bool>::new()));
    {
        let mut threads_guard = active_threads_safe.lock();
        threads_guard.insert(node_id, true);
    }
    
    // 启动节点工作线程
    log_println!("\n🚀 节点-{}: 正式启动节点工作线程", node_id);
    let handle = tokio::spawn(async move {
        // 在这里创建一个新的活动线程状态映射，而不是使用传入的映射
        let active_threads_for_thread = Arc::new(Mutex::new(HashMap::<u64, bool>::new()));
        
        // 确认节点状态而不重新获取锁
        log_println!("📌 节点-{}: 工作线程已启动", node_id);
        
        // 发送一次明确的状态更新，确保显示在UI上
        if let Some(ref callback) = node_callback {
            callback(node_id, format!("🔍 节点工作线程启动，准备获取任务..."));
        }
        
        // 运行节点
        log_println!("🚀 节点-{}: 即将运行主任务循环", node_id);
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
            active_threads_for_thread, // 使用新创建的映射
            node_tx_clone,
        ).await;
        
        // 节点完成时从全局活跃节点集合中移除
        remove_global_active_node(node_id);
        log_println!("🔴 节点-{}: 已从全局活跃节点集合中移除", node_id);
    });
    
    log_println!("✅ 节点-{}: 启动完成，已返回任务句柄", node_id);
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
    active_threads: Arc<Mutex<HashMap<u64, bool>>>,
    node_tx: mpsc::Sender<NodeManagerCommand>,
) {
    // 创建一个停止标志，用于强制退出循环
    let should_stop = Arc::new(AtomicBool::new(false));
    // 重命名为_should_stop_clone避免未使用变量警告
    let _should_stop_clone = should_stop.clone();
    
    // 不再创建自动停止逻辑，让节点持续运行
    
    const MAX_SUBMISSION_RETRIES: usize = 8; // 增加到8次，特别是针对429错误
    const MAX_TASK_RETRIES: usize = 5; // 增加到5次
    const MAX_429_RETRIES: usize = 12; // 专门针对429错误的重试次数
    const MAX_CONSECUTIVE_429S_BEFORE_ROTATION: u32 = 0; // 连续429错误达到此数量时轮转（改为0，确保立即轮转）
    let mut _consecutive_failures = 0; // 改为_consecutive_failures
    let mut proof_count = 0;
    let mut consecutive_429s = 0; // 跟踪连续429错误
    
    // 添加任务获取失败计数，用于触发轮转
    let mut task_fetch_failures = 0;
    const MAX_TASK_FETCH_FAILURES_BEFORE_ROTATION: usize = 1; // 连续获取任务失败1次后触发轮转（立刻轮转）
    
    // 使用传入的事件发送器
    let event_sender = event_sender.clone();
    
    // 创建节点速率限制跟踪器
    let rate_limit_tracker = online::NodeRateLimitTracker::new();
    
    // 创建event_sender的克隆，以便在闭包和后续代码中使用
    let event_sender_for_closure = event_sender.clone();
    
    // 更新节点状态
    let update_status = move |status: String| {
        if let Some(callback) = &status_callback {
            callback(node_id, status.clone());
        }
    };
    
    // 发送事件到UI
    let _send_event = move |msg: String, event_type: crate::events::EventType| {
        let event_sender = event_sender_for_closure.clone();
        tokio::spawn(async move {
            let _ = event_sender
                .send(Event::proof_submitter(msg, event_type))
                .await;
        });
    };
    
    update_status(format!("🚀 启动中"));
    
    // 通知节点管理器节点已启动
    let _ = node_tx.send(NodeManagerCommand::NodeStarted(node_id)).await;
    
    // 不再需要额外输出大量启动日志
    log_println!("🌐 节点-{}: 启动并运行中", node_id);
    
    // 确保节点在active_threads中标记为活跃
    {
        let mut threads_guard = active_threads.lock();
        threads_guard.insert(node_id, true);
    }
    
    // 确保节点在全局活跃节点集合中
    add_global_active_node(node_id);
    
    // 发送一个明确的状态更新
    update_status(format!("�� 节点已启动并运行中 - 准备获取任务"));
    
    // 减少输出，只在详细模式下显示
    if get_verbose_output() {
        log_println!("🚀 节点-{}: 真正开始运行任务循环", node_id);
    }
    
    // 发送一个明确的状态更新到UI
    update_status(format!("🚀 节点-{}: 开始运行任务循环", node_id));
    
    loop {
        // 检查停止标志 - 但我们已经移除了自动设置标志的逻辑，所以这里只会在外部设置时触发
        if should_stop.load(std::sync::atomic::Ordering::SeqCst) {
            update_status("🛑 收到停止信号，正在停止...".to_string());
            // 通知节点管理器当前节点已停止
            let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
            log_println!("🛑 节点-{}: 强制停止", node_id);
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
                    // 成功获取任务，重置失败计数
                    task_fetch_failures = 0;
                    rate_limit_tracker.reset_429_count(node_id).await;
                    consecutive_429s = 0; // 重置连续429计数
                    
                    // 获取节点成功次数
                    let success_count = rate_limit_tracker.get_success_count(node_id).await;
                    
                    // 获取任务成功
                    let timestamp = get_timestamp_efficient();
                    
                    // 更新状态显示成功次数
                    update_status(format!("[{}] 获取任务 ({}/5) (成功: {}次)", timestamp, attempt + 1, success_count));
                    // 更新节点状态
                    set_node_state(node_id, "获取任务中");
                    
                    // 检查是否有该任务的缓存证明
                    if let Some((cached_proof_bytes, cached_proof_hash, attempts)) = orchestrator.get_cached_proof(&task.task_id) {
                        // 有缓存的证明，直接尝试提交
                        update_status(format!("[{}] 使用缓存证明重试提交 (尝试次数: {})", timestamp, attempts + 1));
                        // 更新节点状态
                        set_node_state(node_id, "使用缓存证明提交");
                        
                        // 针对缓存的证明，我们可以进行更多次数的重试，特别是429错误
                        let mut retry_count = 0;
                        let mut rate_limited = false;
                        
                        // 对于缓存的证明，我们可以更积极地重试
                        while retry_count < MAX_429_RETRIES {
                            let attempt_start = Instant::now();
                            match orchestrator.submit_proof(&task.task_id, &cached_proof_hash, cached_proof_bytes.clone(), signing_key.clone()).await {
                                Ok(_) => {
                                    let elapsed = attempt_start.elapsed().as_secs();
                                    update_status(format!("[{}] ✅ 缓存提交成功 (重试 {}/{})，用时 {}s", timestamp, retry_count + 1, MAX_429_RETRIES, elapsed));
                                    // 成功提交证明
                                    proof_count += 1;
                                    _consecutive_failures = 0;
                                    // 使用下划线前缀标记可能未使用的变量
                                    let _success = true; // 设置成功状态
                                    consecutive_429s = 0; // 重置连续429计数
                                    
                                    // 重置429计数
                                    rate_limit_tracker.reset_429_count(node_id).await;
                                    
                                    // 获取成功计数（不增加计数，避免重复计数）
                                    let success_count = rate_limit_tracker.get_success_count(node_id).await;
                                    
                                    let msg = format!("[{}] ✅ 缓存证明提交成功! 证明 #{} 完成 (成功: {}次)", timestamp, proof_count, success_count);
                                    update_status(msg.clone());
                                    
                                    // 发送成功事件
                                    let event_sender_clone = event_sender.clone();
                                    let task_id_clone = task.task_id.clone();
                                    tokio::spawn(async move {
                                        let _ = event_sender_clone
                                            .send(Event::proof_submitter(
                                                format!("Proof submitted successfully for task {}", task_id_clone),
                                                crate::events::EventType::ProofSubmitted,
                                            ))
                                            .await;
                                    });
                                    
                                    // 如果启用了轮转功能，成功提交后轮转到下一个节点
                                    if rotation_data.is_some() {
                                        log_println!("🔄 节点-{}: 证明提交成功，触发轮转", node_id);
                                        let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "证明已被接受", &node_tx, &active_threads).await;
                                        if should_rotate {
                                            if let Some(msg) = status_msg {
                                                update_status(msg);
                                            }
                                            return; // 结束当前节点的处理
                                        } else {
                                            log_println!("⚠️ 节点-{}: 轮转失败，继续使用当前节点", node_id);
                                        }
                                    } else {
                                        log_println!("⚠️ 节点-{}: 轮转功能未启用，继续使用当前节点", node_id);
                                    }
                                    
                                    break;
                                }
                                Err(e) => {
                                    let elapsed = attempt_start.elapsed().as_secs();
                                    update_status(format!("[{}] ❌ 缓存提交失败 (重试 {}/{})，用时 {}s: {}", timestamp, retry_count + 1, MAX_429_RETRIES, elapsed, e));
                                    let error_str = e.to_string();
                                    if error_str.contains("RATE_LIMITED") || error_str.contains("429") {
                                        // 速率限制错误 - 使用随机等待时间
                                        rate_limited = true;
                                        let wait_time = 30 + rand::random::<u64>() % 31; // 30-60秒随机
                                        
                                        // 增加节点的429计数
                                        let _count = rate_limit_tracker.increment_429_count(node_id).await;
                                        consecutive_429s += 1; // 增加连续429计数
                                        
                                        // 如果启用了轮转功能，直接轮转到下一个节点（不管连续429错误数量）
                                        if rotation_data.is_some() {
                                             // 记录429到文件
                                             record_429_event(node_id, "cached submit 429");
                                             // 先更新状态，表明节点遇到429错误（但会立即轮转）
                                             update_status(format!("[{}] 🚫 429限制 - 正在轮转到新节点...", timestamp));
                                            // 更新节点状态
                                            set_node_state(node_id, "遇到429错误，准备轮转");
                                            
                                            log_println!("\n⚠️ 节点-{}: 检测到429错误，立即触发轮转\n", node_id);
                                            log_println!("🔄 节点-{}: 429错误，触发轮转", node_id);
                                            
                                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "检测到429错误", &node_tx, &active_threads).await;
                                            if should_rotate {
                                                if let Some(msg) = status_msg {
                                                    update_status(format!("{}\n🔄 节点已轮转，当前节点处理结束", msg));
                                                }
                                                
                                                // 发送一个显式的停止消息，确保节点真正停止
                                                match node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await {
                                                    Ok(_) => log_println!("🛑 节点-{}: 轮转后成功发送停止信号", node_id),
                                                    Err(e) => log_println!("⚠️ 节点-{}: 轮转后发送停止信号失败: {}", node_id, e),
                                                }
                                                
                                                // 强制关闭此节点，避免继续处理
                                                should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                                log_println!("🛑 节点-{}: 轮转后强制停止", node_id);
                                                
                                                // 立即返回，确保节点不再继续运行
                                                return;
                                            } else {
                                                // 轮转失败但仍然显示原始429消息
                                                log_println!("⚠️ 节点-{}: 轮转失败，将等待后重试", node_id);
                                                update_status(format!("[{}] 🚫 429限制 - 等待{}s后重试 (轮转失败)", 
                                                    timestamp, wait_time));
                                            }
                                        } else {
                                            // 轮转功能未启用，显示普通等待消息
                                            update_status(format!("[{}] 🚫 429限制 - 等待{}s后重试", 
                                                timestamp, wait_time));
                                            log_println!("节点-{}: 429错误 (轮转功能未启用)", node_id);
                                        }
                                        
                                        // 只有在无法轮转的情况下才执行等待
                                        if !rotation_data.is_some() || !should_stop.load(std::sync::atomic::Ordering::SeqCst) {
                                            tokio::time::sleep(Duration::from_secs(wait_time)).await;
                                        }
                                        
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
                                        
                                        // 发送成功事件
                                        let event_sender_clone = event_sender.clone();
                                        let task_id_clone = task.task_id.clone();
                                        tokio::spawn(async move {
                                            let _ = event_sender_clone
                                                .send(Event::proof_submitter(
                                                    format!("Proof already accepted for task {}", task_id_clone),
                                                    crate::events::EventType::ProofSubmitted,
                                                ))
                                                .await;
                                        });
                                        
                                        // 如果启用了轮转功能，成功提交后轮转到下一个节点
                                        if rotation_data.is_some() {
                                            log_println!("🔄 节点-{}: 证明提交成功，触发轮转", node_id);
                                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "证明已被接受", &node_tx, &active_threads).await;
                                            if should_rotate {
                                                if let Some(msg) = status_msg {
                                                    update_status(msg);
                                                }
                                                return; // 结束当前节点的处理
                                            } else {
                                                log_println!("⚠️ 节点-{}: 轮转失败，继续使用当前节点", node_id);
                                            }
                                        } else {
                                            log_println!("⚠️ 节点-{}: 轮转功能未启用，继续使用当前节点", node_id);
                                        }
                                        
                                        break;
                                    } else {
                                        // 重置429计数（非429错误）
                                        rate_limit_tracker.reset_429_count(node_id).await;
                                        consecutive_429s = 0; // 重置连续429计数
                                        
                                        update_status(format!("[{}] ❌ 缓存证明提交失败: {}", timestamp, error_str));
                                        
                                                                                // 检查是否为404错误（任务未找到），如果是则触发节点轮转
                                        if error_str.contains("404") || error_str.contains("NotFoundError") || error_str.contains("Task not found") {
                                            update_status(format!("[{}] 🔍 任务已不存在 (404)，触发节点轮转", timestamp));
                                            retry_count = MAX_429_RETRIES; // 设置为最大值以跳出循环
                                            
                                            // 如果启用了轮转功能，404错误时轮转到下一个节点
                                            if rotation_data.is_some() {
                                                log_println!("🔄 节点-{}: 404错误，触发轮转", node_id);
                                                let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "404错误-任务不存在", &node_tx, &active_threads).await;
                                                if should_rotate {
                                                    if let Some(msg) = status_msg {
                                                        update_status(format!("{}\n🔄 节点已轮转，当前节点处理结束", msg));
                                                    }
                                                    // 发送一个显式的停止消息，确保节点真正停止
                                                    let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                                                    log_println!("🛑 节点-{}: 轮转后显式停止", node_id);
                                                    
                                                    // 设置停止标志
                                                    should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                                    
                                                    // 强制退出当前节点的处理循环
                                                    return;
                                                } else {
                                                    log_println!("⚠️ 节点-{}: 轮转失败，继续使用当前节点", node_id);
                                                }
                                            }
                                            
                                            break; // 立即退出重试循环
                                        }

                                        // 如果不是429错误，我们不需要那么多重试
                                        if retry_count >= 2 {
                                            update_status(format!("[{}] 放弃缓存证明，尝试重新生成...", timestamp));
                                            break;
                                        }
                                        tokio::time::sleep(Duration::from_secs(1)).await;
                                        retry_count += 1;
                                    }
                                }
                            }
                        }
                        
                        // 如果成功提交或达到429重试上限但仍是速率限制，则继续下一个循环
                        if _success || (retry_count >= MAX_429_RETRIES && rate_limited) {
                            if !_success && rate_limited {
                                                                        update_status(format!("[{}] ⚠️ 429限制 - 等待60s后重试", timestamp));
                                tokio::time::sleep(Duration::from_secs(60)).await; // 长时间等待
                            }
                            break;
                        }
                    }
                    
                    // 没有缓存或缓存提交失败，重新生成证明
                    update_status(format!("[{}] 正在生成证明...", timestamp));
                    // 更新节点状态
                    set_node_state(node_id, "生成证明中");
                    
                    match crate::prover::authenticated_proving(&task, &environment, client_id.clone()).await {
                        Ok(proof) => {
                            // 证明生成成功，开始提交
                            update_status(format!("[{}] 正在提交证明...", timestamp));
                            // 更新节点状态
                            set_node_state(node_id, "提交证明中");
                            
                            // 计算哈希（与 0.10.4 保持一致使用 Keccak256）
                            let proof_bytes = postcard::to_allocvec(&proof)
                                .unwrap_or_else(|_| Vec::new());
                            let proof_hash = format!("{:x}", sha3::Keccak256::digest(&proof_bytes));
                            
                            // 提交证明 - 克隆签名密钥以避免所有权问题
                            let mut retry_count = 0;
                            let mut rate_limited = false;
                            
                            while retry_count < MAX_SUBMISSION_RETRIES {
                                let attempt_start = Instant::now();
                                match orchestrator.submit_proof(&task.task_id, &proof_hash, proof_bytes.clone(), signing_key.clone()).await {
                                Ok(_) => {
                                    let elapsed = attempt_start.elapsed().as_secs();
                                    update_status(format!("[{}] ✅ 提交成功 (重试 {}/{})，用时 {}s", timestamp, retry_count + 1, MAX_SUBMISSION_RETRIES, elapsed));
                                    // 成功提交证明
                                    proof_count += 1;
                                    _consecutive_failures = 0;
                                    // 使用下划线前缀标记可能未使用的变量
                                    let _success = true; // 设置成功状态
                                    consecutive_429s = 0; // 重置连续429计数
                                    
                                    // 重置429计数
                                    rate_limit_tracker.reset_429_count(node_id).await;
                                    
                                    // 获取成功计数（不增加计数，避免重复计数）
                                    let success_count = rate_limit_tracker.get_success_count(node_id).await;
                                    
                                    let msg = format!("[{}] ✅ 证明 #{} 完成 (成功: {}次)", timestamp, proof_count, success_count);
                                    update_status(msg.clone());
                                    
                                    // 发送成功事件
                                    let event_sender_clone = event_sender.clone();
                                    tokio::spawn(async move {
                                        let _ = event_sender_clone
                                            .send(Event::proof_submitter(
                                                format!("Proof submitted successfully for task {}", task.task_id),
                                                crate::events::EventType::ProofSubmitted,
                                            ))
                                            .await;
                                    });
                                    
                                    #[cfg(debug_assertions)]
                                    {
                                        log_println!("\n🔍 节点-{}: 证明提交成功，准备轮转...", node_id);
                                        log_println!("🔍 节点-{}: rotation_data是否存在: {}\n", node_id, rotation_data.is_some());
                                    }
                                    
                                    // 如果启用了轮转功能，成功提交后轮转到下一个节点
                                    if rotation_data.is_some() {
                                        log_println!("🔄 节点-{}: 证明提交成功，触发轮转", node_id);
                                        let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "成功提交证明", &node_tx, &active_threads).await;
                                        if should_rotate {
                                            if let Some(msg) = status_msg {
                                                update_status(msg);
                                            }
                                            // 发送一个显式的停止消息，确保节点真正停止
                                            let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                                            log_println!("🛑 节点-{}: 轮转后显式停止", node_id);
                                            
                                            // 设置停止标志
                                            should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                            
                                            // 强制退出当前节点的处理循环
                                            return;
                                        } else {
                                            log_println!("⚠️ 节点-{}: 轮转失败，继续使用当前节点", node_id);
                                        }
                                    } else {
                                        log_println!("⚠️ 节点-{}: 轮转功能未启用，继续使用当前节点", node_id);
                                    }
                                    
                                    break;
                                }
                                Err(e) => {
                                    let elapsed = attempt_start.elapsed().as_secs();
                                    update_status(format!("[{}] ❌ 提交失败 (重试 {}/{})，用时 {}s: {}", timestamp, retry_count + 1, MAX_SUBMISSION_RETRIES, elapsed, e));
                                    let error_str = e.to_string();
                                    if error_str.contains("RATE_LIMITED") || error_str.contains("429") {
                                        // 速率限制错误
                                        rate_limited = true;
                                        
                                        // 增加节点的429计数
                                        let _count = rate_limit_tracker.increment_429_count(node_id).await;
                                        consecutive_429s += 1; // 增加连续429计数
                                        
                                        // 缓存证明以便后续重试
                                        orchestrator.cache_proof(&task.task_id, &proof_hash, &proof_bytes);
                                        
                                        let wait_time = 3 + rand::random::<u64>() % 4; // 3-6秒随机
                                        
                                        // 如果启用了轮转功能，直接轮转到下一个节点（不管连续429错误数量）
                                        if rotation_data.is_some() {
                                            // 记录429到文件
                                            record_429_event(node_id, "submit 429");
                                            // 先更新状态，表明节点遇到429错误（但会立即轮转）
                                            update_status(format!("[{}] 🚫 429限制 - 正在轮转到新节点...", timestamp));
                                            // 更新节点状态
                                            set_node_state(node_id, "遇到429错误，准备轮转");
                                            
                                            log_println!("\n⚠️ 节点-{}: 检测到429错误，立即触发轮转\n", node_id);
                                            log_println!("🔄 节点-{}: 429错误，触发轮转", node_id);
                                            
                                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "检测到429错误", &node_tx, &active_threads).await;
                                            if should_rotate {
                                                if let Some(msg) = status_msg {
                                                    update_status(msg);
                                                }
                                                return; // 结束当前节点的处理
                                            } else {
                                                log_println!("⚠️ 节点-{}: 轮转失败，继续使用当前节点", node_id);
                                            }
                                        } else {
                                            log_println!("节点-{}: 429错误 (轮转功能未启用)", node_id);
                                        }
                                         
                                        // 即使429，外层不等待，让轮转或上层逻辑处理
                                        break;
                                    } else if error_str.contains("404") || error_str.contains("NotFoundError") || error_str.contains("Task not found") {
                                        update_status(format!("[{}] 🔍 任务已不存在 (404)，触发节点轮转", timestamp));
                                        retry_count = MAX_SUBMISSION_RETRIES; // 直接退出循环
                                        if rotation_data.is_some() {
                                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "404错误-任务不存在", &node_tx, &active_threads).await;
                                            if should_rotate {
                                                if let Some(msg) = status_msg { update_status(msg); }
                                                return;
                                            }
                                        }
                                        break;
                                    } else if error_str.contains("409") || error_str.contains("CONFLICT") || error_str.contains("已提交") {
                                        // 与上方逻辑一致，会视为成功
                                        proof_count += 1;
                                        _consecutive_failures = 0;
                                        let _success = true;
                                        rate_limit_tracker.reset_429_count(node_id).await;
                                        let success_count = rate_limit_tracker.get_success_count(node_id).await;
                                        let msg = format!("[{}] ✅ 证明已被接受 (409) (成功: {}次)", timestamp, success_count);
                                        update_status(msg.clone());
                                        let event_sender_clone = event_sender.clone();
                                        tokio::spawn(async move {
                                            let _ = event_sender_clone
                                                .send(Event::proof_submitter(
                                                    format!("Proof already accepted for task {}", task.task_id),
                                                    crate::events::EventType::ProofSubmitted,
                                                ))
                                                .await;
                                        });
                                        if rotation_data.is_some() {
                                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "证明已被接受", &node_tx, &active_threads).await;
                                            if should_rotate { if let Some(msg) = status_msg { update_status(msg); } return; }
                                        }
                                        break;
                                    } else {
                                        // 非429/404/409错误：按既有0.1s等待策略
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                        retry_count += 1;
                                    }
                                }
                            }
                            }
                            
                            if _success || retry_count >= MAX_SUBMISSION_RETRIES {
                                if !_success {
                                    // 如果是由于速率限制而失败，等待更长时间
                                    if rate_limited {
                                        update_status(format!("[{}] ⚠️ 429限制 - 等待60s后重试", timestamp));
                                        tokio::time::sleep(Duration::from_secs(60)).await;
                                    } else {
                                        update_status(format!("[{}] ⚠️ 提交失败 - 等待0.1s后重试", timestamp));
                                        tokio::time::sleep(Duration::from_millis(100)).await;
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
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                    
                    // 无论成功与否，都退出尝试循环
                    break;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    if error_str.contains("RATE_LIMITED") || error_str.contains("429") {
                        // 速率限制错误
                        let _count = rate_limit_tracker.increment_429_count(node_id).await;
                        consecutive_429s += 1; // 增加连续429计数
                        task_fetch_failures += 1; // 增加任务获取失败计数
                        
                        let wait_time = 3 + rand::random::<u64>() % 4; // 3-6秒随机
                        
                        // 如果启用了轮转功能，直接轮转到下一个节点（不管连续429错误数量）
                        if rotation_data.is_some() {
                            // 记录429到文件
                            record_429_event(node_id, "fetch 429");
                            // 先更新状态，表明节点遇到429错误（但会立即轮转）
                            update_status(format!("[{}] 🚫 429限制 - 正在轮转到新节点...", timestamp));
                             
                            log_println!("\n⚠️ 节点-{}: 检测到429错误，立即触发轮转\n", node_id);
                            log_println!("🔄 节点-{}: 429错误，触发轮转", node_id);
                             
                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "检测到429错误", &node_tx, &active_threads).await;
                            if should_rotate {
                                if let Some(msg) = status_msg {
                                    update_status(format!("{}\n🔄 节点已轮转，当前节点处理结束", msg));
                                }
                                
                                // 发送一个显式的停止消息，确保节点真正停止
                                match node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await {
                                    Ok(_) => log_println!("🛑 节点-{}: 轮转后成功发送停止信号", node_id),
                                    Err(e) => log_println!("⚠️ 节点-{}: 轮转后发送停止信号失败: {}", node_id, e),
                                }
                                
                                // 强制关闭此节点，避免继续处理
                                should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                log_println!("🛑 节点-{}: 轮转后强制停止", node_id);
                                
                                // 立即返回，确保节点不再继续运行
                                return;
                            } else {
                                // 轮转失败但仍然显示原始429消息
                                log_println!("⚠️ 节点-{}: 轮转失败，将等待后重试", node_id);
                                update_status(format!("[{}] 🚫 429限制 - 等待{}s后重试 (轮转失败)", 
                                    timestamp, wait_time));
                            }
                        } else {
                            // 轮转功能未启用，显示普通等待消息
                            update_status(format!("[{}] 🚫 429限制 - 等待{}s后重试", 
                                timestamp, wait_time));
                            log_println!("节点-{}: 429错误 (轮转功能未启用)", node_id);
                        }
                        
                        // 只有在无法轮转的情况下才执行等待
                        if !rotation_data.is_some() || !should_stop.load(std::sync::atomic::Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_secs(wait_time)).await;
                        }
                    } else if error_str.contains("404") || error_str.contains("NOT_FOUND") {
                        // 404错误 - 无可用任务，直接触发节点轮转
                        consecutive_429s = 0; // 重置连续429计数
                        task_fetch_failures += 1; // 增加任务获取失败计数
                        
                        // 重置429计数
                        rate_limit_tracker.reset_429_count(node_id).await;
                        
                        update_status(format!("[{}] 🔍 无可用任务 (404)，触发节点轮转", timestamp));
                        
                        // 如果启用了轮转功能，404错误时立即轮转到下一个节点
                        if rotation_data.is_some() {
                            log_println!("🔄 节点-{}: 404错误，触发轮转", node_id);
                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "404错误-无可用任务", &node_tx, &active_threads).await;
                            if should_rotate {
                                if let Some(msg) = status_msg {
                                    update_status(format!("{}\n🔄 节点已轮转，当前节点处理结束", msg));
                                }
                                // 发送一个显式的停止消息，确保节点真正停止
                                let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                                log_println!("🛑 节点-{}: 轮转后显式停止", node_id);
                                
                                // 设置停止标志
                                should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                
                                // 强制退出当前节点的处理循环
                                return;
                            } else {
                                log_println!("⚠️ 节点-{}: 轮转失败，继续使用当前节点", node_id);
                            }
                        }
                        
                        // 如果轮转失败或未启用轮转，等待后继续
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    } else {
                        // 其他错误
                        _consecutive_failures += 1;
                        consecutive_429s = 0; // 重置连续429计数
                        task_fetch_failures += 1; // 增加任务获取失败计数
                        
                        // 重置429计数
                        rate_limit_tracker.reset_429_count(node_id).await;
                        
                        // 失败重试策略：首次失败就轮转
                        if rotation_data.is_some() && attempt >= 1 {
                            update_status(format!("[{}] ❌ 获取任务失败: {} (第 {}/{}) -> 轮转", timestamp, error_str, attempt, MAX_TASK_RETRIES));
                            log_println!("🔄 节点-{}: 获取任务失败已达到阈值，触发轮转", node_id);
                            let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "获取任务失败-达阈值轮转", &node_tx, &active_threads).await;
                            if should_rotate {
                                if let Some(msg) = status_msg {
                                    update_status(format!("{}\n🔄 节点已轮转，当前节点处理结束", msg));
                                }
                                // 显式停止当前节点
                                let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                                should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                return;
                            } else {
                                // 轮转失败，短暂等待
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        } else {
                        update_status(format!("[{}] ❌ 获取任务失败: {} (尝试 {}/{})", 
                            timestamp, error_str, attempt, MAX_TASK_RETRIES));
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                    attempt += 1;
                }
            }
        }
        
        // 如果所有尝试都失败，等待一段时间后再试
        if !_success && attempt > MAX_TASK_RETRIES {
            update_status(format!("[{}] ⚠️ 获取任务失败，等待后重试...", timestamp));
            
            // 检查是否需要触发轮转 - 如果连续获取任务失败次数达到阈值
            if task_fetch_failures >= MAX_TASK_FETCH_FAILURES_BEFORE_ROTATION && rotation_data.is_some() {
                log_println!("\n⚠️ 节点-{}: 连续获取任务失败{}次，触发轮转 (阈值: {})\n", 
                    node_id, task_fetch_failures, MAX_TASK_FETCH_FAILURES_BEFORE_ROTATION);
                
                log_println!("🔄 节点-{}: 任务获取失败，触发轮转", node_id);
                let (should_rotate, status_msg) = rotate_to_next_node(node_id, &rotation_data, "连续获取任务失败", &node_tx, &active_threads).await;
                if should_rotate {
                    if let Some(msg) = status_msg {
                        update_status(format!("{}\n🔄 节点已轮转，当前节点处理结束", msg));
                    }
                    // 发送一个显式的停止消息，确保节点真正停止
                    let _ = node_tx.send(NodeManagerCommand::NodeStopped(node_id)).await;
                    log_println!("🛑 节点-{}: 轮转后显式停止", node_id);
                    
                    // 设置停止标志
                    should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                    
                    // 强制退出当前节点的处理循环
                    return;
                } else {
                    log_println!("⚠️ 节点-{}: 轮转失败，继续使用当前节点", node_id);
                    // 重置失败计数，避免连续触发轮转
                    task_fetch_failures = 0;
                }
            } else {
                // 如果不需要轮转，等待后继续尝试
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        
        // 如果启用了证明间隔，等待指定时间
        if proof_interval > 0 {
            let wait_time = proof_interval + (rand::random::<u64>() % 2); // 添加0-1秒的随机变化
            update_status(format!("[{}] ⏱️ 等待 {}s 后继续...", timestamp, wait_time));
            tokio::time::sleep(Duration::from_secs(wait_time)).await;
        }
    }
}

// 清理活动节点列表，确保只有真正活动的节点被包含
async fn cleanup_active_nodes(
    active_nodes: &Arc<Mutex<Vec<u64>>>, 
    active_threads: &Arc<Mutex<HashMap<u64, bool>>>,
    max_concurrent: usize
) {
    // 获取当前真正活跃的节点
    let active_node_ids: Vec<u64>;
    {
        let threads_guard = active_threads.lock();
        active_node_ids = threads_guard.iter()
            .filter(|pair| *pair.1)
            .map(|(&id, _)| id)
            .collect();
    }
    
    // 创建一个副本，以便后面可以再次使用
    let active_node_ids_for_empty_check = active_node_ids.clone();
    
    // 如果没有活跃节点，说明可能出现了问题，打印警告
    if active_node_ids_for_empty_check.is_empty() {
        // 检查全局活跃节点集合是否也为空
        let global_active_count = get_global_active_node_count();
        if global_active_count == 0 {
            log_println!("⚠️ 警告: 没有检测到任何活跃节点，这可能是一个问题");
        } else {
            log_println!("⚠️ 警告: 本地活跃节点列表为空，但全局有 {} 个活跃节点，执行强制同步", global_active_count);
            
            // 强制同步全局活跃节点集合 - 但不清空全局集合，而是尝试恢复本地状态
            {
                let global_nodes = GLOBAL_ACTIVE_NODES.lock();
                let mut threads_guard = active_threads.lock();
                
                // 将全局活跃节点添加到本地active_threads中
                for &node_id in global_nodes.iter() {
                    threads_guard.insert(node_id, true);
                    log_println!("🔄 强制同步 - 将全局节点 {} 标记为本地活跃", node_id);
                }
                
                log_println!("🔄 强制同步完成 - 从全局恢复了 {} 个活跃节点", global_nodes.len());
            }
        }
    }
    
    // 如果活跃节点数量超过最大并发数，强制限制
    let active_node_ids_limited = if active_node_ids.len() > max_concurrent {
        log_println!("⚠️ 节点清理: 活跃节点数量 ({}) 超过最大并发数 ({}), 进行限制", 
                active_node_ids.len(), max_concurrent);
        
        // 只保留前max_concurrent个节点
        active_node_ids.iter().take(max_concurrent).cloned().collect::<Vec<u64>>()
    } else {
        active_node_ids
    };
    
    // 获取全局活跃节点集合的当前状态
    let global_active_count = get_global_active_node_count();
    
    // 如果全局活跃节点数量与实际活跃节点数量不一致，打印警告
    if global_active_count != active_node_ids_limited.len() {
        log_println!("⚠️ 节点清理: 全局活跃节点数量 ({}) 与实际活跃节点数量 ({}) 不一致，执行强制同步", 
                global_active_count, active_node_ids_limited.len());
        
        // 强制同步全局活跃节点集合
        sync_global_active_nodes(active_threads, max_concurrent);
    }
    
    // 更新活动节点列表，确保包含所有真正活跃的节点
    {
        let mut nodes_guard = active_nodes.lock();
        
        // 检查当前活动节点列表状态
        if nodes_guard.len() < active_node_ids_limited.len() {
            log_println!("⚠️ 节点清理: 活动节点列表 ({}) 小于实际活跃节点数量 ({}), 需要添加节点", 
                    nodes_guard.len(), active_node_ids_limited.len());
        } else if nodes_guard.len() > max_concurrent {
            log_println!("⚠️ 节点清理: 活动节点列表 ({}) 超过最大并发数 ({}), 需要减少节点", 
                    nodes_guard.len(), max_concurrent);
        }
        
        // 只有在以下情况才执行完全重建:
        // 1. 活动节点列表为空
        // 2. 活动节点列表大小与实际活跃节点数量差异超过2
        // 3. 活动节点列表超过最大并发数
        let should_rebuild = nodes_guard.is_empty() || 
                            (nodes_guard.len() as i64 - active_node_ids_limited.len() as i64).abs() > 2 ||
                            nodes_guard.len() > max_concurrent;
        
        if should_rebuild {
            // 强制清空活动节点列表，以确保下面的操作从零开始，避免累积
            nodes_guard.clear();
            log_println!("🧹 节点清理: 已清空活动节点列表，重新填充");
            
            // 填充最多max_concurrent个活跃节点
            let nodes_to_add = active_node_ids_limited.iter()
                .take(max_concurrent)
                .cloned()
                .collect::<Vec<u64>>();
            
            if !nodes_to_add.is_empty() {
                nodes_guard.extend(nodes_to_add.clone());
                log_println!("✅ 节点清理: 已添加{}个活跃节点到活动列表 (完全重建)", nodes_guard.len());
                
                // 确保这些节点真正启动 - 添加一个标记，表示这些节点需要启动
                log_println!("🚀 节点清理: 标记这些节点需要重新启动");
                
                // 将这些节点在active_threads中标记为非活跃，以便后续启动
                {
                    let mut threads_guard = active_threads.lock();
                    for &node_id in &nodes_to_add {
                        threads_guard.insert(node_id, false);
                        log_println!("🚀 节点清理: 节点-{} 标记为需要启动", node_id);
                    }
                }
            } else {
                log_println!("⚠️ 节点清理: 没有活跃节点可添加，活动列表为空");
                
                // 如果没有活跃节点，尝试启动紧急恢复
                log_println!("🚨 紧急情况: 没有活跃节点，尝试启动紧急恢复流程");
                
                // 从全局活跃节点集合中获取节点
                let global_nodes = GLOBAL_ACTIVE_NODES.lock();
                if !global_nodes.is_empty() {
                    // 选择最多max_concurrent个节点添加到活动列表
                    let emergency_nodes: Vec<u64> = global_nodes.iter()
                        .take(max_concurrent)
                        .copied()
                        .collect();
                    
                    nodes_guard.extend(emergency_nodes.iter());
                    log_println!("🚨 紧急恢复: 从全局活跃节点集合中添加了 {} 个节点到活动列表", emergency_nodes.len());
                    
                    // 将这些节点在active_threads中标记为非活跃，以便后续启动
                    {
                        let mut threads_guard = active_threads.lock();
                        for &node_id in &emergency_nodes {
                            threads_guard.insert(node_id, false);
                            log_println!("🚨 紧急恢复: 节点-{} 标记为需要启动", node_id);
                        }
                    }
                }
            }
        } else {
            // 增量更新: 移除不再活跃的节点
            nodes_guard.retain(|node_id| {
                let active_threads_guard = active_threads.lock();
                active_threads_guard.get(node_id).copied().unwrap_or(false)
            });
            
            // 如果节点数量小于最大并发数，尝试添加更多节点
            if nodes_guard.len() < max_concurrent {
                // 找出当前不在列表中但是活跃的节点
                let missing_nodes: Vec<u64> = active_node_ids_limited.iter()
                    .filter(|id| !nodes_guard.contains(id))
                    .cloned()
                    .collect();
                
                // 添加缺失的节点，直到达到最大并发数
                for node_id in missing_nodes {
                    if nodes_guard.len() >= max_concurrent {
                        break;
                    }
                    nodes_guard.push(node_id);
                }
                
                log_println!("✅ 节点清理: 增量更新 - 当前活动节点数量: {}", nodes_guard.len());
            }
        }
        
        // 再次确保活动节点列表不超过最大并发数
        if nodes_guard.len() > max_concurrent {
            log_println!("⚠️ 节点清理: 活动节点列表仍然超出限制 ({} > {}), 强制截断", 
                    nodes_guard.len(), max_concurrent);
            nodes_guard.truncate(max_concurrent);
            log_println!("✅ 节点清理: 已强制截断活动节点列表至 {} 个节点", nodes_guard.len());
        }
        
        // 获取当前真正活跃的节点
        let current_active_node_ids: Vec<u64> = {
            let threads_guard = active_threads.lock();
            threads_guard.iter()
                .filter(|pair| *pair.1)
                .map(|(&id, _)| id)
                .collect()
        };
        
        // 如果活动节点列表为空但有活跃节点，这是一个严重问题
        if nodes_guard.is_empty() && !current_active_node_ids.is_empty() {
            log_println!("🚨 严重错误: 活动节点列表为空，但有 {} 个活跃节点", current_active_node_ids.len());
            // 紧急添加活跃节点
            nodes_guard.extend(current_active_node_ids.iter().take(max_concurrent).cloned());
            log_println!("🚨 紧急修复: 已添加 {} 个活跃节点到活动列表", nodes_guard.len());
        }
        
        // 检查全局活跃节点集合是否为空或数量不足，如果是但活动节点列表不为空，则同步
        let global_active_count = get_global_active_node_count();
        if (global_active_count == 0 || global_active_count < max_concurrent / 2) && !nodes_guard.is_empty() {
            log_println!("🚨 紧急情况: 全局活跃节点数量不足 ({}), 但活动节点列表有 {} 个节点", 
                    global_active_count, nodes_guard.len());
            
            // 紧急同步全局活跃节点集合
            let mut global_nodes = GLOBAL_ACTIVE_NODES.lock();
            
            // 如果全局活跃节点集合为空，则完全重建
            if global_nodes.is_empty() {
                for &node_id in nodes_guard.iter().take(max_concurrent) {
                    global_nodes.insert(node_id);
                    
                    // 同时确保节点在active_threads中标记为非活跃，以便后续启动
                    let mut threads_guard = active_threads.lock();
                    threads_guard.insert(node_id, false);
                    log_println!("🚨 紧急恢复: 节点-{} 添加到全局活跃节点集合并标记为需要启动", node_id);
                }
                log_println!("🚨 紧急修复: 已添加 {} 个节点到空的全局活跃节点集合", global_nodes.len());
            } 
            // 如果全局活跃节点数量不足，则补充
            else if global_nodes.len() < max_concurrent / 2 {
                // 找出不在全局集合中的节点
                let nodes_to_sync: Vec<u64> = nodes_guard.iter()
                    .filter(|&&node_id| !global_nodes.contains(&node_id))
                    .take(max_concurrent - global_nodes.len())
                    .copied()
                    .collect();
                
                // 添加这些节点
                for &node_id in &nodes_to_sync {
                    global_nodes.insert(node_id);
                    
                    // 同时确保节点在active_threads中标记为非活跃，以便后续启动
                    let mut threads_guard = active_threads.lock();
                    threads_guard.insert(node_id, false);
                    log_println!("🚨 紧急恢复: 节点-{} 添加到全局活跃节点集合并标记为需要启动", node_id);
                }
                
                log_println!("🚨 紧急修复: 已添加 {} 个节点到全局活跃节点集合，现有 {} 个", 
                        nodes_to_sync.len(), global_nodes.len());
            }
            
            // 打印当前活跃节点状态
            log_println!("📊 节点清理后状态: 活动节点列表 {} 个, 全局活跃节点集合 {} 个", 
                    nodes_guard.len(), global_nodes.len());
            
            // 打印所有活跃节点ID，便于调试
            log_println!("📋 活动节点列表: {:?}", *nodes_guard);
            log_println!("📋 全局活跃节点: {:?}", global_nodes.iter().collect::<Vec<&u64>>());
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
            let task = Task::new(i.to_string(), format!("Task {}", i), vec![1, 2, 3], crate::task::TaskType::ProofRequired);
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
                    log_println!("Received task {}: {:?}", received, task);
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

