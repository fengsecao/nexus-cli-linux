//! Offline Workers
//!
//! Handles local compute operations that don't require network access:
//! - Task dispatching to workers
//! - Proof computation (authenticated and anonymous)
//! - Worker management

use crate::environment::Environment;
use crate::error_classifier::ErrorClassifier;
use crate::events::{Event, EventType};
use crate::prover::authenticated_proving;
use crate::remote::client::RemoteProverClient;
use crate::task::Task;
use log::{debug, warn};
use nexus_sdk::stwo::seq::Proof;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

/// Spawns a dispatcher that forwards tasks to available workers in round-robin fashion.
pub fn start_dispatcher(
    mut task_receiver: mpsc::Receiver<Task>,
    worker_senders: Vec<mpsc::Sender<Task>>,
    mut shutdown: broadcast::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut next_worker = 0;
        loop {
            tokio::select! {
                Some(task) = task_receiver.recv() => {
                    let target = next_worker % worker_senders.len();
                    if let Err(_e) = worker_senders[target].send(task).await {
                        // Channel is closed, stop dispatching tasks
                        return;
                    }
                    next_worker += 1;
                }

                _ = shutdown.recv() => {
                    break;
                }
            }
        }
    })
}

/// Spawns a set of worker tasks that receive tasks and send prover events.
///
/// # Arguments
/// * `num_workers` - The number of worker tasks to spawn.
/// * `results_sender` - The channel to emit results (task and proof).
/// * `prover_event_sender` - The channel to send prover events to the main thread.
///
/// # Returns
/// A tuple containing:
/// * A vector of `Sender<Task>` for each worker, allowing tasks to be sent to them.
/// * A vector of `JoinHandle<()>` for each worker, allowing the main thread to await their completion.
pub fn start_workers(
    num_workers: usize,
    results_sender: mpsc::Sender<(Task, Proof)>,
    event_sender: mpsc::Sender<Event>,
    shutdown: broadcast::Receiver<()>,
    environment: Environment,
    client_id: String,
) -> (Vec<mpsc::Sender<Task>>, Vec<JoinHandle<()>>) {
    let mut senders = Vec::with_capacity(num_workers);
    let mut handles = Vec::with_capacity(num_workers);

    for worker_id in 0..num_workers {
        let (task_sender, mut task_receiver) = mpsc::channel::<Task>(8);
        // Clone senders and receivers for each worker.
        let prover_event_sender = event_sender.clone();
        let results_sender = results_sender.clone();
        let mut shutdown_rx = shutdown.resubscribe();
        let client_id = client_id.clone();
        let error_classifier = ErrorClassifier::new();
        let environment_clone = environment.clone();
        let client_id_clone = client_id.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        let message = format!("Worker {} received shutdown signal", worker_id);
                        let _ = prover_event_sender
                            .send(Event::prover(worker_id, message, EventType::Shutdown))
                            .await;
                        break; // Exit the loop on shutdown signal
                    }
                    // Check if there are tasks to process
                    Some(task) = task_receiver.recv() => {
                        let task_id = task.task_id.clone();
                        debug!("Worker {} processing task {}", worker_id, task_id);
                        // 根据运行模式决定本地或远程证明
                        let mode = std::env::var("NEXUS_MODE").unwrap_or_else(|_| "normal".to_string());
                        let prove_result = if mode == "client" {
                            let base_url = std::env::var("REMOTE_URL").unwrap_or_else(|_| "http://127.0.0.1:8088".to_string());
                            let auth = std::env::var("REMOTE_AUTH_TOKEN").ok();
                            let poll_ms = std::env::var("REMOTE_POLL_MS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(1000);
                            let timeout_secs = std::env::var("REMOTE_TIMEOUT_SECS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(3600);
                            let rpc = RemoteProverClient::new(base_url, auth, poll_ms, timeout_secs);
                            // 记录远程统计并更新状态
                            if let Ok(node_id) = task.task_id.split('-').next().unwrap_or("0").parse::<u64>() {
                                crate::prover_runtime::remote_stats_inc_received(node_id);
                                crate::prover_runtime::set_node_state(node_id, "已提交远程作业，等待计算...");
                            }
                            // 支持在节点轮转/关闭时取消远程作业
                            // let _cancel_rpc = rpc.clone(); // 预留精确取消接口
                            match tokio::select! {
                                biased;
                                res = rpc.request_proof(&task) => res,
                                _ = shutdown_rx.recv() => {
                                    // best effort cancel: 解析job_id目前不对外，暂无法取消具体job
                                    // 可在未来将job_id存入状态以支持精确取消
                                    return; // 直接返回，worker退出
                                }
                            } {
                                Ok((proof, _hash)) => {
                                    if let Ok(node_id) = task.task_id.split('-').next().unwrap_or("0").parse::<u64>() {
                                        crate::prover_runtime::remote_stats_inc_completed(node_id);
                                        crate::prover_runtime::set_node_state(node_id, "远程作业完成，准备提交...");
                                    }
                                    Ok(proof)
                                },
                                Err(e) => {
                                    if let Ok(node_id) = task.task_id.split('-').next().unwrap_or("0").parse::<u64>() {
                                        crate::prover_runtime::remote_stats_inc_failed(node_id);
                                        crate::prover_runtime::set_node_state(node_id, &format!("远程作业失败: {}", e));
                                    }
                                    Err(crate::prover::ProverError::Stwo(e))
                                },
                            }
                        } else {
                            authenticated_proving(&task, &environment_clone, client_id_clone.clone()).await
                        };

                        match prove_result {
                            Ok(proof) => {
                                debug!("Worker {} completed task {}", worker_id, task_id);
                                let message = format!(
                                    "Proof completed successfully (Prover {})",
                                    worker_id
                                );
                                let _ = prover_event_sender
                                    .send(Event::prover(worker_id, message, EventType::Success))
                                    .await;
                                let _ = results_sender.send((task, proof)).await;
                            }
                            Err(e) => {
                                warn!("Worker {} failed to process task {}: {}", worker_id, task_id, e);
                                let log_level = error_classifier.classify_worker_error(&e);
                                let message = format!("Error: {}", e);
                                let event = Event::prover_with_level(worker_id, message, EventType::Error, log_level);
                                if event.should_display() {
                                    let _ = prover_event_sender.send(event).await;
                                }

                                // For analytics errors, continue processing but don't send result
                                // For other errors, also don't send result (task failed)
                            }
                        }
                    }
                    else => break,
                }
            }
        });

        senders.push(task_sender);
        handles.push(handle);
    }

    (senders, handles)
}

/// Starts anonymous workers that repeatedly prove a program with hardcoded inputs.
pub async fn start_anonymous_workers(
    num_workers: usize,
    shutdown: broadcast::Receiver<()>,
    environment: Environment,
    client_id: String,
) -> (mpsc::Receiver<Event>, Vec<JoinHandle<()>>) {
    let (event_sender, event_receiver) = mpsc::channel::<Event>(100);
    let mut join_handles = Vec::new();
    for worker_id in 0..num_workers {
        let prover_event_sender = event_sender.clone();
        let mut shutdown_rx = shutdown.resubscribe(); // clone receiver for each worker
        let client_id = client_id.clone();
        let error_classifier = ErrorClassifier::new();
        let environment_clone = environment.clone();
        let client_id_clone = client_id.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        let message = format!("Worker {} received shutdown signal", worker_id);
                        let _ = prover_event_sender
                            .send(Event::prover(worker_id, message, EventType::Shutdown))
                            .await;
                        break; // Exit the loop on shutdown signal
                    }

                    _ = tokio::time::sleep(Duration::from_millis(300)) => {
                        // Perform work
                        debug!("Anonymous worker {} generating proof", worker_id);
                        match crate::prover::prove_anonymously(&environment_clone, client_id_clone.clone()).await {
                            Ok(_proof) => {
                                debug!("Anonymous worker {} completed proof", worker_id);
                                let message = "Anonymous proof completed successfully".to_string();
                                let _ = prover_event_sender
                                    .send(Event::prover(worker_id, message, EventType::Success)).await;
                            }
                            Err(e) => {
                                warn!("Anonymous worker {} failed to generate proof: {}", worker_id, e);
                                let log_level = error_classifier.classify_worker_error(&e);
                                let message = format!("Anonymous Worker: Error - {}", e);
                                let event = Event::prover_with_level(worker_id, message, EventType::Error, log_level);
                                if event.should_display() {
                                    let _ = prover_event_sender.send(event).await;
                                }

                                // For analytics errors, this is non-critical, continue the loop
                                // For other errors, also continue (anonymous mode keeps retrying)
                            }
                        }
                    }
                }
            }
        });
        join_handles.push(handle);
    }

    (event_receiver, join_handles)
}
