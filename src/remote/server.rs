use axum::{routing::{get, post, delete}, Router, extract::{Path, State}, Json};
use axum::http::{HeaderMap, StatusCode};
use serde_json::json;
use std::{collections::{HashMap, VecDeque}, sync::Arc};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;
use crate::remote::types::{JobSubmitRequest, JobSubmitResponse, JobStatusResponse};
use crate::prover::authenticated_proving;
use crate::task::Task;
use crate::environment::Environment;
use sha3::{Digest, Keccak256};

#[derive(Clone)]
struct AppState {
    jobs: Arc<RwLock<HashMap<String, JobRecord>>>,
    job_handles: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
    environment: Environment,
    client_id: String,
    max_concurrency: usize,
    semaphore: Arc<tokio::sync::Semaphore>,
    auth_token: Option<String>,
    recent_successes: Arc<Mutex<VecDeque<std::time::Instant>>>, // 近5分钟成功滑窗
    recent_errors: Arc<Mutex<VecDeque<String>>>, // 最近错误消息(最多5条)
    job_timeout_secs: u64,
}

#[derive(Clone)]
struct JobRecord {
    req: JobSubmitRequest,
    state: Arc<Mutex<String>>, // queued|running|succeeded|failed
    started_at: std::time::Instant,
    error: Arc<Mutex<Option<String>>>,
    result: Arc<Mutex<Option<Vec<u8>>>>, // postcard-serialized proof
    result_hash: Arc<Mutex<Option<String>>>,
}

pub async fn run_server(listen: &str, environment: Environment, client_id: String, max_concurrency: usize, auth_token: Option<String>, job_timeout_secs: u64) -> Result<(), String> {
    let state = AppState {
        jobs: Arc::new(RwLock::new(HashMap::new())),
        job_handles: Arc::new(Mutex::new(HashMap::new())),
        environment,
        client_id,
        max_concurrency,
        semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrency.max(1))),
        auth_token,
        recent_successes: Arc::new(Mutex::new(VecDeque::new())),
        recent_errors: Arc::new(Mutex::new(VecDeque::new())),
        job_timeout_secs,
    };

    let app_state_for_monitor = state.clone();

    let app = Router::new()
        .route("/v1/jobs", post(submit_job))
        .route("/v1/jobs/:id", get(get_job).delete(cancel_job))
        .with_state(state);

    // Server monitor: print metrics every second
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        let start = std::time::Instant::now();
        loop {
            ticker.tick().await;
            let jobs = app_state_for_monitor.jobs.read().await;
            let mut queued = 0usize;
            let mut running = 0usize;
            let mut succeeded = 0usize;
            let mut failed = 0usize;
            let mut running_list: Vec<(String, u64)> = Vec::new();
            for (id, rec) in jobs.iter() {
                let st = rec.state.lock().await.clone();
                match st.as_str() {
                    "queued" => queued += 1,
                    "running" => {
                        running += 1;
                        running_list.push((id.clone(), rec.started_at.elapsed().as_secs()));
                    }
                    "succeeded" => succeeded += 1,
                    "failed" => failed += 1,
                    _ => {}
                }
            }
            running_list.sort_by_key(|(_, secs)| std::cmp::Reverse(*secs));
            let total = jobs.len();
            drop(jobs);

            // 近5分钟吞吐（次/分钟）
            let mut rs = app_state_for_monitor.recent_successes.lock().await;
            let now = std::time::Instant::now();
            let cutoff = now - std::time::Duration::from_secs(5 * 60);
            while let Some(&t) = rs.front() { if t < cutoff { rs.pop_front(); } else { break; } }
            let window_secs = rs.front().map(|&t| now.saturating_duration_since(t).as_secs_f64()).unwrap_or(0.0);
            let per_min = if rs.is_empty() || window_secs == 0.0 { 0.0 } else { (rs.len() as f64) / (window_secs / 60.0) };
            drop(rs);

            if queued > app_state_for_monitor.max_concurrency * 2 {
                println!("⚠️ 队列拥堵: 排队 {} 个，建议提升并发或增加计算节点", queued);
            }
            println!(
                "🖥️ RemoteProver 服务 | 运行:{}s | 总:{} 排队:{} 运行:{} 成功:{} 失败:{} | 并发上限:{} | 吞吐(近5分): {:.2} 次/分",
                start.elapsed().as_secs(), total, queued, running, succeeded, failed, app_state_for_monitor.max_concurrency, per_min
            );
            if !running_list.is_empty() {
                println!("运行中(前10):");
                for (jid, secs) in running_list.iter().take(10) {
                    println!("  - {} 运行 {}s", jid, secs);
                }
            }
            // 最近错误
            let errs = app_state_for_monitor.recent_errors.lock().await;
            if !errs.is_empty() {
                println!("最近错误:");
                for e in errs.iter() { println!("  - {}", e); }
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(listen).await.map_err(|e| e.to_string())?;
    axum::serve(listener, app).await.map_err(|e| e.to_string())
}

async fn submit_job(State(state): State<AppState>, headers: HeaderMap, Json(req): Json<JobSubmitRequest>) -> (StatusCode, Json<JobSubmitResponse>) {
    // Optional bearer auth
    if let Some(expected) = &state.auth_token {
        let ok = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|h| h == format!("Bearer {}", expected))
            .unwrap_or(false);
        if !ok { return (StatusCode::UNAUTHORIZED, Json(JobSubmitResponse { job_id: String::new(), accepted: false })); }
    }
    let job_id = Uuid::new_v4().to_string();
    let record = JobRecord {
        req,
        state: Arc::new(Mutex::new("queued".to_string())),
        started_at: std::time::Instant::now(),
        error: Arc::new(Mutex::new(None)),
        result: Arc::new(Mutex::new(None)),
        result_hash: Arc::new(Mutex::new(None)),
    };
    {
        let mut jobs = state.jobs.write().await;
        jobs.insert(job_id.clone(), record.clone());
    }

    let st = state.clone();
    let handle = tokio::spawn(async move {
        let _permit = st.semaphore.acquire().await.expect("semaphore");
        *record.state.lock().await = "running".to_string();
        // phase: received
        let task = Task {
            task_id: record.req.task_id.clone(),
            program_id: record.req.program_id.clone(),
            public_inputs: record.req.public_inputs_list.get(0).cloned().unwrap_or_default(),
            public_inputs_list: record.req.public_inputs_list.clone(),
            task_type: <crate::nexus_orchestrator::TaskType as core::convert::TryFrom<i32>>::try_from(record.req.task_type).unwrap_or(crate::nexus_orchestrator::TaskType::ProofRequired),
        };
        // 标记 phase 为 computing
        let fut = authenticated_proving(&task, &st.environment, st.client_id.clone());
        let res = if st.job_timeout_secs > 0 {
            tokio::time::timeout(std::time::Duration::from_secs(st.job_timeout_secs), fut).await
                .map_err(|_| "job timeout".to_string())
                .and_then(|r| r.map_err(|e| e.to_string()))
        } else {
            fut.await.map_err(|e| e.to_string())
        };
        match res {
            Ok(proof) => {
                // 标记 phase 为 returning
                let bytes = postcard::to_allocvec(&proof).unwrap_or_default();
                let hash = format!("{:x}", Keccak256::digest(&bytes));
                *record.result.lock().await = Some(bytes);
                *record.result_hash.lock().await = Some(hash);
                *record.state.lock().await = "succeeded".to_string();
                // 记录成功滑窗
                let mut rs = st.recent_successes.lock().await;
                rs.push_back(std::time::Instant::now());
                while rs.len() > 10000 { rs.pop_front(); }
            }
            Err(e) => {
                *record.error.lock().await = Some(e.to_string());
                *record.state.lock().await = "failed".to_string();
                // 记录错误消息（最多5条）
                let mut er = st.recent_errors.lock().await;
                er.push_back(format!("{}: {}", record.req.task_id, e));
                while er.len() > 5 { er.pop_front(); }
            }
        }
    });
    {
        let mut hs = state.job_handles.lock().await;
        hs.insert(job_id.clone(), handle);
    }

    (StatusCode::OK, Json(JobSubmitResponse { job_id, accepted: true }))
}

async fn get_job(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> (StatusCode, Json<JobStatusResponse>) {
    // Optional bearer auth
    if let Some(expected) = &state.auth_token {
        let ok = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|h| h == format!("Bearer {}", expected))
            .unwrap_or(false);
        if !ok { return (StatusCode::UNAUTHORIZED, Json(JobStatusResponse { job_id: id, state: "unauthorized".into(), phase: None, elapsed_secs: 0, error: Some("unauthorized".into()), proof: None, proof_hash: None })); }
    }
    let jobs = state.jobs.read().await;
    if let Some(rec) = jobs.get(&id) {
        let st = rec.state.lock().await.clone();
        let err = rec.error.lock().await.clone();
        let proof = rec.result.lock().await.clone();
        let phash = rec.result_hash.lock().await.clone();
        let elapsed = rec.started_at.elapsed().as_secs();
        let phase = match (st.as_str(), proof.is_some()) {
            ("queued", _) => Some("received".to_string()),
            ("running", false) => Some("computing".to_string()),
            ("succeeded", true) => Some("returning".to_string()),
            _ => None,
        };
        return (StatusCode::OK, Json(JobStatusResponse { job_id: id, state: st, phase, elapsed_secs: elapsed, error: err, proof, proof_hash: phash }));
    }
    (StatusCode::NOT_FOUND, Json(JobStatusResponse { job_id: id, state: "not_found".to_string(), phase: None, elapsed_secs: 0, error: Some("not found".into()), proof: None, proof_hash: None }))
}

async fn cancel_job(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> (StatusCode, Json<serde_json::Value>) {
    // Optional bearer auth
    if let Some(expected) = &state.auth_token {
        let ok = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|h| h == format!("Bearer {}", expected))
            .unwrap_or(false);
        if !ok { return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "error": "unauthorized"}))); }
    }
    // Abort running task if present
    if let Some(handle) = state.job_handles.lock().await.remove(&id) {
        handle.abort();
    }
    // Mark job as canceled
    if let Some(rec) = state.jobs.write().await.get_mut(&id) {
        *rec.state.lock().await = "failed".to_string();
        *rec.error.lock().await = Some("canceled".to_string());
    }
    (StatusCode::OK, Json(json!({"ok": true})))
}


