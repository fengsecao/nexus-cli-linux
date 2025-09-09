//! Online Workers
//!
//! Handles network-dependent operations including:
//! - Task fetching from the orchestrator
//! - Proof submission to the orchestrator
//! - Network error handling with exponential backoff

use crate::consts::prover::{
    BACKOFF_DURATION, BATCH_SIZE, LOW_WATER_MARK, MAX_404S_BEFORE_GIVING_UP, QUEUE_LOG_INTERVAL,
    TASK_QUEUE_SIZE,
};
use crate::error_classifier::{ErrorClassifier, LogLevel};
use crate::events::Event;
use crate::prover_runtime::set_node_state;
use crate::orchestrator::Orchestrator;
use crate::orchestrator::error::OrchestratorError;
use crate::task::Task;
use crate::task_cache::TaskCache;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::SigningKey;
use sha3::{Digest, Keccak256};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use nexus_sdk::stwo::seq::Proof;
use chrono;
use once_cell::sync::Lazy;

// 全局取任务调度器：限制同时取任务的并发数，默认1（串行放号）
static GLOBAL_FETCH_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| {
    let permits = std::env::var("NEXUS_FETCH_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1);
    Semaphore::new(permits)
});

/// 节点速率限制跟踪器，用于记录每个节点的连续429计数
#[derive(Debug, Clone, Default)]
pub struct NodeRateLimitTracker {
    node_429_counts: Arc<Mutex<HashMap<u64, u32>>>,
    node_success_counts: Arc<Mutex<HashMap<u64, u32>>>, // 添加节点成功计数
}

impl NodeRateLimitTracker {
    pub fn new() -> Self {
        Self {
            node_429_counts: Arc::new(Mutex::new(HashMap::new())),
            node_success_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 增加指定节点的429计数
    pub async fn increment_429_count(&self, node_id: u64) -> u32 {
        let mut counts = self.node_429_counts.lock().await;
        let count = counts.entry(node_id).or_insert(0);
        *count += 1;
        *count
    }

    /// 重置指定节点的429计数
    pub async fn reset_429_count(&self, node_id: u64) {
        let mut counts = self.node_429_counts.lock().await;
        counts.insert(node_id, 0);
    }

    /// 获取指定节点的当前429计数
    #[allow(dead_code)]
    pub async fn get_429_count(&self, node_id: u64) -> u32 {
        let counts = self.node_429_counts.lock().await;
        *counts.get(&node_id).unwrap_or(&0)
    }
    
    /// 增加指定节点的成功计数
    pub async fn increment_success_count(&self, node_id: u64) -> u32 {
        let mut counts = self.node_success_counts.lock().await;
        let count = counts.entry(node_id).or_insert(0);
        *count += 1;
        *count
    }
    
    /// 获取指定节点的成功计数
    pub async fn get_success_count(&self, node_id: u64) -> u32 {
        let counts = self.node_success_counts.lock().await;
        *counts.get(&node_id).unwrap_or(&0)
    }
}

/// State for managing task fetching behavior
pub struct TaskFetchState {
    last_fetch_time: std::time::Instant,
    backoff_duration: Duration,
    last_queue_log_time: std::time::Instant,
    queue_log_interval: Duration,
    #[allow(dead_code)]
    error_classifier: ErrorClassifier,
    consecutive_429s: u32, // 添加连续429计数器
}

impl TaskFetchState {
    pub fn new() -> Self {
        Self {
            last_fetch_time: std::time::Instant::now()
                - Duration::from_millis(BACKOFF_DURATION + 1000), // Allow immediate first fetch
            backoff_duration: Duration::from_millis(BACKOFF_DURATION), // Start with 30 second backoff
            last_queue_log_time: std::time::Instant::now(),
            queue_log_interval: Duration::from_millis(QUEUE_LOG_INTERVAL), // Log queue status every 30 seconds
            error_classifier: ErrorClassifier::new(),
            consecutive_429s: 0,
        }
    }

    pub fn should_log_queue_status(&mut self) -> bool {
        // Log queue status every QUEUE_LOG_INTERVAL seconds regardless of queue level
        self.last_queue_log_time.elapsed() >= self.queue_log_interval
    }

    pub fn should_fetch(&self, tasks_in_queue: usize) -> bool {
        tasks_in_queue < LOW_WATER_MARK && self.last_fetch_time.elapsed() >= self.backoff_duration
    }

    pub fn record_fetch_attempt(&mut self) {
        self.last_fetch_time = std::time::Instant::now();
    }

    pub fn record_queue_log(&mut self) {
        self.last_queue_log_time = std::time::Instant::now();
    }

    pub fn reset_backoff(&mut self) {
        self.backoff_duration = Duration::from_millis(BACKOFF_DURATION);
    }

    pub fn increase_backoff_for_rate_limit(&mut self) {
        self.backoff_duration = std::cmp::min(
            self.backoff_duration * 2,
            Duration::from_millis(BACKOFF_DURATION * 2),
        );
    }

    pub fn increase_backoff_for_error(&mut self) {
        self.backoff_duration = std::cmp::min(
            self.backoff_duration * 2,
            Duration::from_millis(BACKOFF_DURATION * 2),
        );
    }

    // 增加429连续计数
    pub fn increment_429_count(&mut self) {
        self.consecutive_429s += 1;
    }

    // 重置429连续计数
    pub fn reset_429_count(&mut self) {
        self.consecutive_429s = 0;
    }

    // 获取当前429连续计数
    #[allow(dead_code)]
    pub fn get_429_count(&self) -> u32 {
        self.consecutive_429s
    }

    pub fn set_backoff_from_server(&mut self, seconds: u32) {
        self.backoff_duration = Duration::from_secs(seconds as u64);
    }
}

/// Fetches tasks from the orchestrator and place them in the task queue.
/// Uses demand-driven fetching: only fetches when queue drops below LOW_WATER_MARK.
pub async fn fetch_prover_tasks(
    node_id: u64,
    verifying_key: VerifyingKey,
    orchestrator_client: Box<dyn Orchestrator>,
    sender: mpsc::Sender<Task>,
    event_sender: mpsc::Sender<Event>,
    mut shutdown: broadcast::Receiver<()>,
    recent_tasks: TaskCache,
    rate_limit_tracker: NodeRateLimitTracker,
) {
    let mut state = TaskFetchState::new();

    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                let tasks_in_queue = TASK_QUEUE_SIZE - sender.capacity();

                // Log queue status every QUEUE_LOG_INTERVAL seconds regardless of queue level
                if state.should_log_queue_status() {
                    state.record_queue_log();
                    log_queue_status(&event_sender, tasks_in_queue, &state).await;
                }

                // 显示排队/退避倒计时（无论是否触发取任务）
                let remain = state
                    .backoff_duration
                    .as_secs()
                    .saturating_sub(state.last_fetch_time.elapsed().as_secs());
                if GLOBAL_FETCH_SEMAPHORE.available_permits() == 0 {
                    set_node_state(node_id, "排队等待取任务许可...");
                } else if !state.should_fetch(tasks_in_queue) && remain > 0 {
                    set_node_state(node_id, &format!("等待 {}s 后再取任务", remain));
                }

                // Attempt fetch if conditions are met
                if state.should_fetch(tasks_in_queue) {
                    // 若当前无可用取任务许可，则提示排队；否则标记将取任务
                    if GLOBAL_FETCH_SEMAPHORE.available_permits() == 0 { set_node_state(node_id, "排队等待取任务许可..."); }
                    else { set_node_state(node_id, "获取任务 (1/5)"); }
                    // 串行放号：获取全局取任务许可
                    let _permit = GLOBAL_FETCH_SEMAPHORE.acquire().await.expect("semaphore poisoned");

                    // 为避免同时撞限，增加100-400ms随机抖动
                    let jitter_ms = 100 + (rand::random::<u64>() % 301);
                    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

                    if let Err(should_return) = attempt_task_fetch(
                        &*orchestrator_client,
                        &node_id,
                        verifying_key,
                        &sender,
                        &event_sender,
                        &recent_tasks,
                        &mut state,
                        &rate_limit_tracker,
                    ).await {
                        if should_return {
                            return;
                        }
                    }
                    // _permit在此作用域结束时自动释放
                }
            }
        }
    }
}

/// Attempt to fetch tasks with timeout and error handling
async fn attempt_task_fetch(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
    state: &mut TaskFetchState,
    rate_limit_tracker: &NodeRateLimitTracker,
) -> Result<(), bool> {
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            format!(
                "Fetching tasks (queue: {} tasks)",
                TASK_QUEUE_SIZE - sender.capacity()
            ),
            crate::events::EventType::Refresh,
            LogLevel::Debug,
        ))
        .await;

    // Add timeout to prevent hanging
    let fetch_future = fetch_task_batch(
        orchestrator_client,
        node_id,
        verifying_key,
        BATCH_SIZE,
        event_sender,
    );
    let timeout_duration = Duration::from_secs(60); // 60 second timeout

    match tokio::time::timeout(timeout_duration, fetch_future).await {
        Ok(fetch_result) => match fetch_result {
            Ok(tasks) => {
                // Record successful fetch attempt timing
                state.record_fetch_attempt();
                handle_fetch_success(tasks, sender, event_sender, recent_tasks, state, rate_limit_tracker).await
            }
            Err(e) => {
                // Record failed fetch attempt timing
                state.record_fetch_attempt();
                handle_fetch_error(e, event_sender, state, node_id, rate_limit_tracker).await;
                Ok(())
            }
        },
        Err(_timeout) => {
            // Handle timeout case
            state.record_fetch_attempt();
            let _ = event_sender
                .send(Event::task_fetcher_with_level(
                    format!("Fetch timeout after {}s", timeout_duration.as_secs()),
                    crate::events::EventType::Error,
                    LogLevel::Warn,
                ))
                .await;
            // Increase backoff for timeout
            state.increase_backoff_for_error();
            // 重置节点特定的429计数
            rate_limit_tracker.reset_429_count(*node_id).await;
            Ok(())
        }
    }
}

/// Log the current queue status
async fn log_queue_status(
    event_sender: &mpsc::Sender<Event>,
    tasks_in_queue: usize,
    state: &TaskFetchState,
) {
    let time_since_last = state.last_fetch_time.elapsed();
    let backoff_secs = state.backoff_duration.as_secs();

    let message = if state.should_fetch(tasks_in_queue) {
        format!("Queue low: {} tasks, ready to fetch", tasks_in_queue)
    } else if tasks_in_queue < LOW_WATER_MARK {
        format!(
            "Queue: {} tasks, waiting {}s before next fetch",
            tasks_in_queue,
            backoff_secs.saturating_sub(time_since_last.as_secs())
        )
    } else {
        format!("Queue: {} tasks, healthy", tasks_in_queue)
    };

    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            message,
            crate::events::EventType::Status,
            LogLevel::Debug,
        ))
        .await;
}

/// Handle successful task fetch
async fn handle_fetch_success(
    tasks: Vec<Task>,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
    state: &mut TaskFetchState,
    rate_limit_tracker: &NodeRateLimitTracker,
) -> Result<(), bool> {
    if tasks.is_empty() {
        handle_empty_task_response(sender, event_sender, state).await;
        return Ok(());
    }

    let (added_count, duplicate_count) =
        process_fetched_tasks(tasks.clone(), sender, event_sender, recent_tasks).await?;

    log_fetch_results(added_count, duplicate_count, sender, event_sender, state, rate_limit_tracker).await;
    
    // 成功获取任务，重置429计数
    if added_count > 0 {
        // 从任务列表中获取第一个任务的节点ID
        if let Some(task) = tasks.first() {
            // 从task_id中提取节点ID
            let node_id_str = task.task_id.split('-').next().unwrap_or("0");
            if let Ok(node_id) = node_id_str.parse::<u64>() {
                rate_limit_tracker.reset_429_count(node_id).await;
            }
        }
    }
    
    Ok(())
}

/// Handle empty task response from server
async fn handle_empty_task_response(
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
) {
    let tasks_in_queue = TASK_QUEUE_SIZE - sender.capacity();
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            format!("No new tasks available (queue: {} tasks)", tasks_in_queue),
            crate::events::EventType::Status,
            LogLevel::Info,
        ))
        .await;

    // Reset backoff on empty response - this is normal
    state.reset_backoff();
}

/// Process fetched tasks and handle duplicates
async fn process_fetched_tasks(
    tasks: Vec<Task>,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
) -> Result<(usize, usize), bool> {
    let mut added_count = 0;
    let mut duplicate_count = 0;

    for task in tasks {
        if recent_tasks.contains(&task.task_id).await {
            duplicate_count += 1;
            continue;
        }
        recent_tasks.insert(task.task_id.clone()).await;

        if sender.send(task.clone()).await.is_err() {
            let _ = event_sender
                .send(Event::task_fetcher(
                    "Task queue is closed".to_string(),
                    crate::events::EventType::Shutdown,
                ))
                .await;
            return Err(true); // Signal caller to return
        }
        added_count += 1;
    }

    Ok((added_count, duplicate_count))
}

/// Log fetch results and handle backoff logic
async fn log_fetch_results(
    added_count: usize,
    duplicate_count: usize,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
    rate_limit_tracker: &NodeRateLimitTracker,
) {
    if added_count > 0 {
        log_successful_fetch(added_count, sender, event_sender, rate_limit_tracker).await;
        state.reset_backoff();
    } else if duplicate_count > 0 {
        handle_all_duplicates(duplicate_count, event_sender, state).await;
    }
}

/// Log successful task fetch with queue status
async fn log_successful_fetch(
    added_count: usize,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    rate_limit_tracker: &NodeRateLimitTracker,
) {
    let tasks_in_queue = TASK_QUEUE_SIZE - sender.capacity();
    
    // 使用默认节点ID
    let default_node_id = 0;
    let success_count = rate_limit_tracker.get_success_count(default_node_id).await;
    let success_count_str = format!(" (成功: {}次)", success_count);
    
    let message = if added_count > 0 {
        format!(
            "Added {} new tasks (queue: {} tasks){}",
            added_count, tasks_in_queue, success_count_str
        )
    } else {
        format!("No new tasks added (queue: {} tasks){}", tasks_in_queue, success_count_str)
    };

    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            message,
            crate::events::EventType::Success,
            LogLevel::Info,
        ))
        .await;
}

/// Handle case where all fetched tasks were duplicates
async fn handle_all_duplicates(
    duplicate_count: usize,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
) {
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            format!("All {} tasks were duplicates", duplicate_count),
            crate::events::EventType::Warning,
            LogLevel::Info,
        ))
        .await;

    // Increase backoff when we get all duplicates
    state.increase_backoff_for_error();
}

/// Handle fetch errors with appropriate backoff
async fn handle_fetch_error(
    error: OrchestratorError,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
    node_id: &u64,
    rate_limit_tracker: &NodeRateLimitTracker,
) {
    // 获取节点成功次数
    let success_count = rate_limit_tracker.get_success_count(*node_id).await;
    
    // Classify error and determine appropriate response
    let (message, error_type, log_level) = match error {
        OrchestratorError::Http { status, ref message, .. } => {
            if status == 429 {
                // Rate limiting requires special handling
                if let Some(retry_after) = error.get_retry_after_seconds() {
                    state.set_backoff_from_server(retry_after);
                    let _ = event_sender
                        .send(Event::task_fetcher_with_level(
                            format!(
                                "[{}] 429限流: 服务端要求 Retry-After={}s",
                                chrono::Local::now().format("%H:%M:%S"),
                                retry_after
                            ),
                            crate::events::EventType::Warning,
                            LogLevel::Warn,
                        ))
                        .await;
                    // 把节点状态也更新为“等待Xs后重试”
                    set_node_state(*node_id, &format!("等待 {}s 后再取任务", retry_after));
                } else {
                    state.increase_backoff_for_rate_limit();
                }
                state.increment_429_count(); // 保留原有的计数器
                
                // 增加节点特定的429计数
                let _count = rate_limit_tracker.increment_429_count(*node_id).await;
                
                // 计算等待时间（秒）
                let wait_seconds = state.backoff_duration.as_secs();
                
                (
                    format!("[{}] 🚫 429限制 - 等待{}s后重试", 
                            chrono::Local::now().format("%H:%M:%S"),
                            wait_seconds),
                    crate::events::EventType::Warning,
                    LogLevel::Warn,
                )
            } else if status == 404 {
                // 404 is normal when no tasks are available
                state.reset_backoff();
                state.reset_429_count(); // 重置原有的计数器
                
                // 重置节点特定的429计数
                rate_limit_tracker.reset_429_count(*node_id).await;
                
                (
                    format!("[{}] 无可用任务 (404) (成功: {}次)", 
                            chrono::Local::now().format("%H:%M:%S"), 
                            success_count),
                    crate::events::EventType::Status,
                    LogLevel::Info,
                )
            } else {
                // Other HTTP errors
                state.increase_backoff_for_error();
                state.reset_429_count(); // 重置原有的计数器
                
                // 重置节点特定的429计数
                rate_limit_tracker.reset_429_count(*node_id).await;
                
                (
                    format!("[{}] HTTP错误 {}: {} (成功: {}次)", 
                            chrono::Local::now().format("%H:%M:%S"),
                            status, message, success_count),
                    crate::events::EventType::Error,
                    LogLevel::Error,
                )
            }
        }
        _ => {
            // Non-HTTP errors (network, etc)
            state.increase_backoff_for_error();
            state.reset_429_count(); // 重置原有的计数器
            
            // 重置节点特定的429计数
            rate_limit_tracker.reset_429_count(*node_id).await;
            
            (
                format!("[{}] 网络错误: {} (成功: {}次)", 
                        chrono::Local::now().format("%H:%M:%S"),
                        error, success_count),
                crate::events::EventType::Error,
                LogLevel::Error,
            )
        }
    };

    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            message,
            error_type,
            log_level,
        ))
        .await;
}

/// Fetch a batch of tasks from the orchestrator
async fn fetch_task_batch(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    batch_size: usize,
    event_sender: &mpsc::Sender<Event>,
) -> Result<Vec<Task>, OrchestratorError> {
    // First try to get existing assigned tasks
    if let Some(existing_tasks) = try_get_existing_tasks(orchestrator_client, node_id).await? {
        return Ok(existing_tasks);
    }

    // If no existing tasks, try to get new ones
    fetch_new_tasks_batch(
        orchestrator_client,
        node_id,
        verifying_key,
        batch_size,
        event_sender,
    )
    .await
}

/// Try to get existing assigned tasks
async fn try_get_existing_tasks(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
) -> Result<Option<Vec<Task>>, OrchestratorError> {
    match orchestrator_client.get_tasks(&node_id.to_string()).await {
        Ok(tasks) => {
            if !tasks.is_empty() {
                Ok(Some(tasks))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            // If getting existing tasks fails, try to get new ones
            if matches!(e, OrchestratorError::Http { status: 404, .. }) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Fetch a batch of new tasks from the orchestrator
async fn fetch_new_tasks_batch(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    batch_size: usize,
    event_sender: &mpsc::Sender<Event>,
) -> Result<Vec<Task>, OrchestratorError> {
    let mut new_tasks = Vec::new();
    let mut consecutive_404s = 0;

    for i in 0..batch_size {
        match orchestrator_client
            .get_proof_task(&node_id.to_string(), verifying_key)
            .await
        {
            Ok(task) => {
                new_tasks.push(task);
                consecutive_404s = 0; // Reset counter on success
            }
            Err(OrchestratorError::Http { status: 429, .. }) => {
                let _ = event_sender
                    .send(Event::task_fetcher_with_level(
                        format!(
                            "fetch_task_batch: Hit rate limit (429) on attempt #{}",
                            i + 1
                        ),
                        crate::events::EventType::Refresh,
                        LogLevel::Debug,
                    ))
                    .await;
                // Rate limited, return what we have
                break;
            }
            Err(OrchestratorError::Http { status: 404, .. }) => {
                consecutive_404s += 1;
                let _ = event_sender
                    .send(Event::task_fetcher_with_level(
                        format!("fetch_task_batch: No task available (404) on attempt #{}, consecutive_404s: {}", i + 1, consecutive_404s),
                        crate::events::EventType::Refresh,
                        LogLevel::Debug,
                    ))
                    .await;

                if consecutive_404s >= MAX_404S_BEFORE_GIVING_UP {
                    let _ = event_sender
                        .send(Event::task_fetcher_with_level(
                            format!(
                                "fetch_task_batch: Too many 404s ({}), giving up",
                                consecutive_404s
                            ),
                            crate::events::EventType::Refresh,
                            LogLevel::Debug,
                        ))
                        .await;
                    break;
                }
                // Continue trying more tasks
            }
            Err(e) => {
                let _ = event_sender
                    .send(Event::task_fetcher_with_level(
                        format!(
                            "fetch_task_batch: get_proof_task #{} failed with error: {:?}",
                            i + 1,
                            e
                        ),
                        crate::events::EventType::Refresh,
                        LogLevel::Debug,
                    ))
                    .await;
                return Err(e);
            }
        }
    }

    Ok(new_tasks)
}

/// Submits proofs to the orchestrator
pub async fn submit_proofs(
    signing_key: SigningKey,
    orchestrator: Box<dyn Orchestrator>,
    num_workers: usize,
    mut results: mpsc::Receiver<(Task, Proof)>,
    event_sender: mpsc::Sender<Event>,
    mut shutdown: broadcast::Receiver<()>,
    successful_tasks: TaskCache,
    rate_limit_tracker: NodeRateLimitTracker,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut completed_count = 0;
        let mut last_stats_time = std::time::Instant::now();
        let stats_interval = Duration::from_secs(60);

        loop {
            tokio::select! {
                maybe_item = results.recv() => {
                    match maybe_item {
                        Some((task, proof)) => {
                            if let Some(success) = process_proof_submission(
                                task,
                                proof,
                                &*orchestrator,
                                &signing_key,
                                num_workers,
                                &event_sender,
                                &successful_tasks,
                                &rate_limit_tracker,
                            ).await {
                                if success {
                                    completed_count += 1;
                                }
                            }

                            // Check if it's time to report stats (avoid timer starvation)
                            if last_stats_time.elapsed() >= stats_interval {
                                report_performance_stats(&event_sender, completed_count, last_stats_time).await;
                                completed_count = 0;
                                last_stats_time = std::time::Instant::now();
                            }
                        }
                        None => break,
                    }
                }

                _ = tokio::time::sleep(stats_interval) => {
                    // Fallback timer in case there's no activity
                    report_performance_stats(&event_sender, completed_count, last_stats_time).await;
                    completed_count = 0;
                    last_stats_time = std::time::Instant::now();
                }

                _ = shutdown.recv() => break,
            }
        }
    })
}

/// Report performance statistics
async fn report_performance_stats(
    event_sender: &mpsc::Sender<Event>,
    completed_count: u64,
    last_stats_time: std::time::Instant,
) {
    let elapsed = last_stats_time.elapsed();
    let tasks_per_minute = if elapsed.as_secs() > 0 {
        (completed_count as f64 * 60.0) / elapsed.as_secs() as f64
    } else {
        0.0
    };

    let msg = format!(
        "Performance: {} tasks in {:.1}s ({:.1} tasks/min)",
        completed_count,
        elapsed.as_secs_f64(),
        tasks_per_minute
    );
    let _ = event_sender
        .send(Event::proof_submitter_with_level(
            msg,
            crate::events::EventType::Refresh,
            LogLevel::Info,
        ))
        .await;
}

/// Process a single proof submission
/// Returns Some(true) if successful, Some(false) if failed, None if should skip
async fn process_proof_submission(
    task: Task,
    proof: Proof,
    orchestrator: &dyn Orchestrator,
    signing_key: &SigningKey,
    num_workers: usize,
    event_sender: &mpsc::Sender<Event>,
    successful_tasks: &TaskCache,
    rate_limit_tracker: &NodeRateLimitTracker,
) -> Option<bool> {
    // Check for duplicate submissions
    if successful_tasks.contains(&task.task_id).await {
        let msg = format!(
            "Ignoring proof for previously submitted task {}",
            task.task_id
        );
        let _ = event_sender
            .send(Event::proof_submitter(msg, crate::events::EventType::Error))
            .await;
        return None; // Skip this task
    }

    // Serialize proof and derive hash
    let proof_bytes = postcard::to_allocvec(&proof).expect("Failed to serialize proof");
    let proof_hash = format!("{:x}", Keccak256::digest(&proof_bytes));
    // Package for 0.10.10 API: legacy single proof plus multi-proof vector (single element for compatibility)
    let proofs_vec = vec![proof_bytes.clone()];
    let individual_hashes = vec![proof_hash.clone()];
    // Convert our TaskType (now proto type) passthrough

    // Submit to orchestrator
    match orchestrator
        .submit_proof(
            &task.task_id,
            &proof_hash,
            proof_bytes,
            proofs_vec,
            signing_key.clone(),
            num_workers,
            task.task_type,
            &individual_hashes,
        )
        .await
    {
        Ok(_) => {
            handle_submission_success(&task, event_sender, successful_tasks, rate_limit_tracker).await;
            Some(true)
        }
        Err(e) => {
            handle_submission_error(&task, e, event_sender, rate_limit_tracker).await;
            Some(false)
        }
    }
}

/// Handle successful proof submission
async fn handle_submission_success(
    task: &Task,
    event_sender: &mpsc::Sender<Event>,
    successful_tasks: &TaskCache,
    rate_limit_tracker: &NodeRateLimitTracker,
) {
    // Record successful submission to prevent duplicates
    let _ = successful_tasks.insert(task.task_id.clone()).await;

    // 解析节点ID - 从任务ID中提取
    let node_id_str = task.task_id.split('-').next().unwrap_or("0");
    let node_id = node_id_str.parse::<u64>().unwrap_or(0);
    
    // 增加节点的成功计数
    let success_count = rate_limit_tracker.increment_success_count(node_id).await;

    // Send success event
    let _ = event_sender
        .send(Event::proof_submitter(
            format!(
                "Proof submitted successfully for task {} (success count: {})",
                task.task_id, success_count
            ),
            crate::events::EventType::ProofSubmitted,
        ))
        .await;
}

/// Handle proof submission error
async fn handle_submission_error(
    task: &Task,
    error: OrchestratorError,
    event_sender: &mpsc::Sender<Event>,
    rate_limit_tracker: &NodeRateLimitTracker,
) {
    // 从task_id中提取节点ID
    let node_id_str = task.task_id.split('-').next().unwrap_or("0");
    let node_id = node_id_str.parse::<u64>().ok();
    
    // 获取节点成功次数
    let success_count = if let Some(node_id) = node_id {
        rate_limit_tracker.get_success_count(node_id).await
    } else {
        0
    };
    
    // Determine the error type and log level based on the error
    let (message, log_level) = match error {
        OrchestratorError::Http { status, ref message, .. } => {
            if status == 429 {
                // 增加429计数
                let count = if let Some(node_id) = node_id {
                    rate_limit_tracker.increment_429_count(node_id).await
                } else {
                    0
                };
                
                // Rate limiting is a warning, not an error
                (
                    format!("Rate limited (429) for task {}: {} (连续429: {}次, 成功: {}次)", task.task_id, message, count, success_count),
                    LogLevel::Warn,
                )
            } else if status == 409 {
                // 重置429计数
                if let Some(node_id) = node_id {
                    rate_limit_tracker.reset_429_count(node_id).await;
                }
                
                // Conflict (duplicate submission) is a warning
                (
                    format!("Duplicate proof for task {}: {} (成功: {}次)", task.task_id, message, success_count),
                    LogLevel::Warn,
                )
            } else {
                // 重置429计数
                if let Some(node_id) = node_id {
                    rate_limit_tracker.reset_429_count(node_id).await;
                }
                
                // Other HTTP errors
                (
                    format!("HTTP error {} for task {}: {} (成功: {}次)", status, task.task_id, message, success_count),
                    LogLevel::Error,
            )
        }
        }
        _ => {
            // 重置429计数
            if let Some(node_id) = node_id {
                rate_limit_tracker.reset_429_count(node_id).await;
            }
            
            // Non-HTTP errors
            (
                format!("Submission error for task {}: {} (成功: {}次)", task.task_id, error, success_count),
                LogLevel::Error,
            )
        }
    };

    // Send the error event
    let _ = event_sender
        .send(Event::proof_submitter_with_level(
            message,
            crate::events::EventType::Error,
            log_level,
        ))
        .await;
}

