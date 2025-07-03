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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use parking_lot::Mutex;
use once_cell::sync::Lazy;
use rand;
use log::{debug, warn};
use crate::orchestrator_client_enhanced::EnhancedOrchestratorClient;
use sha3::Digest;
use postcard;
use std::sync::Arc;

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

    // Task fetching
    let (task_sender, task_receiver) = mpsc::channel::<Task>(TASK_QUEUE_SIZE);
    let verifying_key = signing_key.verifying_key();
    let fetch_prover_tasks_handle = {
        let orchestrator = orchestrator.clone();
        let event_sender = event_sender.clone();
        let shutdown = shutdown.resubscribe(); // Clone the receiver for task fetching
        tokio::spawn(async move {
            online::fetch_prover_tasks(
                node_id,
                verifying_key,
                Box::new(orchestrator),
                task_sender,
                event_sender,
                shutdown,
                enqueued_tasks,
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
    
    // 按序启动各节点
    for (index, node_id) in nodes.iter().enumerate() {
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
                    node_id, index + 1, nodes.len(), actual_delay);
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
        
        // 获取密钥
        let signing_key = match crate::key_manager::load_or_generate_signing_key() {
            Ok(key) => key,
            Err(e) => {
                warn!("节点 {} 加载签名密钥失败: {}", node_id, e);
                // 使用Arc包装的回调
                if let Some(callback_arc) = &status_callback_arc {
                    callback_arc(*node_id, format!("加载密钥失败: {}", e));
                }
                continue;
            }
        };
        
        let node_id = *node_id;
        // 使用增强版客户端
        let enhanced_orchestrator = EnhancedOrchestratorClient::new(environment.clone());
    let shutdown_rx = shutdown.resubscribe();
        let environment = environment.clone();
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
        
        let handle = tokio::spawn(async move {
            run_memory_optimized_node(
                node_id,
                signing_key,
                enhanced_orchestrator,
                num_workers_per_node,
                proof_interval,
                environment,
                client_id,
                shutdown_rx,
            node_callback,
            event_sender_clone,
            ).await;
        });
        
        join_handles.push(handle);
    }
    
    (event_receiver, join_handles)
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
) {
    const MAX_SUBMISSION_RETRIES: usize = 8; // 增加到8次，特别是针对429错误
    const MAX_TASK_RETRIES: usize = 5; // 增加到5次
    const MAX_429_RETRIES: usize = 12; // 专门针对429错误的重试次数
    let mut consecutive_failures = 0;
    let mut proof_count = 0;
    
    // 使用传入的事件发送器
    let event_sender = event_sender.clone();
    
    // 更新节点状态
    let update_status = |status: String| {
        if let Some(callback) = &status_callback {
            callback(node_id, status.clone());
        }
    };
    
    // 发送事件到UI
    let send_event = |msg: String, event_type: crate::events::EventType| {
        let event_sender = event_sender.clone();
        tokio::spawn(async move {
            let _ = event_sender
                .send(Event::proof_submitter(msg, event_type))
                .await;
        });
    };
    
    update_status(format!("🚀 启动中"));
    
    loop {
        // 首先检查关闭信号
        if shutdown.try_recv().is_ok() {
            update_status("已停止".to_string());
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
            update_status("🧹 执行内存碎片整理...".to_string());
            let result = defragmenter.defragment().await;
            update_status(format!("内存: {:.1}% → {:.1}% (释放 {:.1}%)",
                             result.memory_before * 100.0,
                             result.memory_after * 100.0,
                             result.memory_freed_percentage()));
        }
        
        let timestamp = get_timestamp_efficient();
        let mut attempt = 1;
        let mut success = false;
        
        // 尝试获取任务并生成证明
        while attempt <= MAX_TASK_RETRIES {
            update_status(format!("[{}] 获取任务 ({}/{})", timestamp, attempt, MAX_TASK_RETRIES));
            
            let verifying_key = signing_key.verifying_key();
            match orchestrator.get_task(&node_id.to_string(), &verifying_key).await {
                Ok(task) => {
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
                                    consecutive_failures = 0;
                                    success = true;
                                    let msg = format!("[{}] ✅ 缓存证明提交成功! 证明 #{} 完成", timestamp, proof_count);
                                    update_status(msg.clone());
                                    send_event(format!("Proof submitted successfully #{}", proof_count), crate::events::EventType::ProofSubmitted);
                                    break;
                                }
                                Err(e) => {
                                    let error_str = e.to_string();
                                    if error_str.contains("RATE_LIMITED") || error_str.contains("429") {
                                        // 速率限制错误 - 使用随机等待时间
                                        rate_limited = true;
                                        let wait_time = 30 + rand::random::<u64>() % 31; // 30-60秒随机
                                        update_status(format!("[{}] 🚫 速率限制 (429) - 等待 {}s (重试 {}/{})", 
                                            timestamp, wait_time, retry_count + 1, MAX_429_RETRIES));
                                        tokio::time::sleep(Duration::from_secs(wait_time)).await;
                                        retry_count += 1;
                                        continue;
                                    } else if error_str.contains("409") || error_str.contains("CONFLICT") || error_str.contains("已提交") {
                                        // 证明已经被提交，视为成功
                                        let msg = format!("[{}] ✅ 证明已被接受 (409)", timestamp);
                                        update_status(msg.clone());
                                        proof_count += 1;
                                        consecutive_failures = 0;
                                        success = true;
                                        send_event(format!("Proof already accepted #{}", proof_count), crate::events::EventType::ProofSubmitted);
                                        break;
                                    } else {
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
                        if success || (retry_count >= MAX_429_RETRIES && rate_limited) {
                            if !success && rate_limited {
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
                                    consecutive_failures = 0;
                                    success = true;
                                        let msg = format!("[{}] ✅ 证明 #{} 完成", timestamp, proof_count);
                                        update_status(msg.clone());
                                        send_event(format!("Proof submitted successfully #{}", proof_count), crate::events::EventType::ProofSubmitted);
                                    break;
                                }
                                Err(e) => {
                                    let error_str = e.to_string();
                                    if error_str.contains("RATE_LIMITED") || error_str.contains("429") {
                                        // 速率限制错误 - 使用随机等待时间
                                            rate_limited = true;
                                            let wait_time = 30 + rand::random::<u64>() % 31; // 30-60秒随机
                                            update_status(format!("[{}] 🚫 速率限制 (429) - 等待 {}s (重试 {}/{})", 
                                                timestamp, wait_time, retry_count + 1, MAX_SUBMISSION_RETRIES));
                                        tokio::time::sleep(Duration::from_secs(wait_time)).await;
                                        } else if error_str.contains("409") || error_str.contains("CONFLICT") || error_str.contains("已提交") {
                                                                                    // 证明已经被提交，视为成功
                                        let msg = format!("[{}] ✅ 证明已被接受 (409)", timestamp);
                                        update_status(msg.clone());
                                        proof_count += 1;
                                        consecutive_failures = 0;
                                        success = true;
                                        send_event(format!("Proof already accepted #{}", proof_count), crate::events::EventType::ProofSubmitted);
                                        break;
                                    } else {
                                            update_status(format!("[{}] ❌ 提交失败 (重试 {}/{}): {}", 
                                                timestamp, retry_count + 1, MAX_SUBMISSION_RETRIES, error_str));
                                        
                                        // 检查是否为404错误（任务未找到），如果是则不再重试
                                        if error_str.contains("404") || error_str.contains("NotFoundError") || error_str.contains("Task not found") {
                                            update_status(format!("[{}] 🔍 任务已不存在 (404)，停止重试并获取新任务", timestamp));
                                            success = false; // 设置为false以获取新任务
                                            break; // 立即退出重试循环
                                        }
                                        
                                        tokio::time::sleep(Duration::from_secs(2)).await;
                                    }
                                        retry_count += 1;
                                    }
                                }
                            }
                            
                            // 如果成功提交或达到重试上限但仍是速率限制，则继续下一个循环
                            if success || (retry_count >= MAX_SUBMISSION_RETRIES && rate_limited) {
                                if !success && rate_limited {
                                    update_status(format!("[{}] ⚠️ 提交重试次数已达上限，等待一段时间后再尝试", timestamp));
                                    tokio::time::sleep(Duration::from_secs(60)).await; // 长时间等待
                                }
                                break;
                            }
                            
                            // 如果所有重试都失败，则增加尝试计数
                            if !success {
                                    attempt += 1;
                            }
                        }
                        Err(e) => {
                            update_status(format!("[{}] ❌ 证明生成失败: {}", timestamp, e));
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            attempt += 1;
                        }
                    }
                }
                Err(e) => {
                    let error_str = e.to_string();
                    if error_str.contains("RATE_LIMITED") || error_str.contains("429") {
                        // 速率限制错误 - 使用随机等待时间
                        let wait_time = 40 + rand::random::<u64>() % 41; // 40-80秒随机
                        update_status(format!("[{}] 🚫 速率限制 (429) - 等待 {}s", timestamp, wait_time));
                        tokio::time::sleep(Duration::from_secs(wait_time)).await;
                    } else {
                        update_status(format!("[{}] ❌ 获取任务失败: {}", timestamp, error_str));
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                    attempt += 1;
                }
            }
            
            // 检查关闭信号
            if shutdown.try_recv().is_ok() {
                update_status("已停止".to_string());
                return;
            }
        }
        
        if success {
            // 发送分析事件
            let _ = crate::analytics::track(
                "cli_proof_node_batch_v3".to_string(),
                serde_json::json!({
                    "node_id": node_id,
                    "proof_count": proof_count,
                }),
                &environment,
                client_id.clone(),
            ).await;
            
            // 等待指定的证明间隔
            tokio::time::sleep(Duration::from_secs(proof_interval)).await;
        } else {
            consecutive_failures += 1;
            update_status(format!("[{}] ⚠️ 所有尝试均失败 ({}/∞)", timestamp, consecutive_failures));
            
            // 失败后等待时间比正常证明间隔长一些
            tokio::time::sleep(Duration::from_secs((proof_interval + 5).min(15))).await;
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
