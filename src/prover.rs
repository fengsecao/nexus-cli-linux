use crate::analytics::track;
use crate::environment::Environment;
use crate::task::Task;
use crate::system::{check_memory_pressure, perform_memory_cleanup, get_memory_usage_ratio}; 
use crate::utils::system::MemoryDefragmenter;
use log::{debug, error};
use nexus_sdk::stwo::seq::Proof;
use nexus_sdk::{KnownExitCodes, Local, Prover, Viewable, stwo::seq::Stwo};
use serde_json::json;
use thiserror::Error;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use once_cell::sync::Lazy;
use lazy_static::lazy_static;

#[derive(Error, Debug)]
pub enum ProverError {
    #[error("Stwo prover error: {0}")]
    Stwo(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("Malformed task: {0}")]
    MalformedTask(String),

    #[error("Guest Program error: {0}")]
    GuestProgram(String),

    #[error("Analytics tracking error: {0}")]
    Analytics(String),
    
    #[error("Rate limited (429): {0}")]
    RateLimited(String),
}

// 全局证明器实例 - 用于多节点复用
lazy_static! {
    static ref GLOBAL_PROVER_FAST_FIB: RwLock<Option<Arc<Stwo<Local>>>> = RwLock::new(None);
    static ref GLOBAL_PROVER_INITIAL: RwLock<Option<Arc<Stwo<Local>>>> = RwLock::new(None);
    static ref PROVER_INIT_LOCK: Mutex<()> = Mutex::new(());
}

// 全局内存碎片整理器
static GLOBAL_DEFRAGMENTER: Lazy<Arc<MemoryDefragmenter>> = Lazy::new(|| {
    Arc::new(MemoryDefragmenter::new())
});

/// 获取或创建内存优化的fib_input证明器实例
pub async fn get_or_create_default_prover() -> Result<Arc<Stwo<Local>>, ProverError> {
    // 快速路径：已初始化则直接返回
    if let Some(prover) = &*GLOBAL_PROVER_FAST_FIB.read().await {
        return Ok(prover.clone());
    }
    
    // 获取初始化锁（防止多线程同时初始化）
    let _guard = PROVER_INIT_LOCK.lock().await;
    // 再次检查以避免竞争条件
    if let Some(prover) = &*GLOBAL_PROVER_FAST_FIB.read().await {
        return Ok(prover.clone());
    }
    
    // 高级内存检查和清理
    if GLOBAL_DEFRAGMENTER.should_defragment().await {
        debug!("🧹 证明器初始化前执行内存碎片整理...");
        let result = GLOBAL_DEFRAGMENTER.defragment().await;
        debug!("   内存优化: {:.1}% → {:.1}% (释放 {:.1}%)", 
              result.memory_before * 100.0, 
              result.memory_after * 100.0,
              result.memory_freed_percentage());
    }
    
    // 检查内存状态
    let memory_ratio = get_memory_usage_ratio();
    if memory_ratio > 0.90 {
        debug!("⚠️ 内存使用率过高 ({:.1}%)，执行清理...", memory_ratio * 100.0);
        perform_memory_cleanup();
    }
    
    // 初始化证明器
    let prover = get_default_stwo_prover()
        .map_err(|e| ProverError::Stwo(format!("创建证明器失败: {}", e)))?;
    let prover_arc = Arc::new(prover);
    
    // 更新全局实例
    *GLOBAL_PROVER_FAST_FIB.write().await = Some(prover_arc.clone());
    
    // 记录内存使用情况和缓存统计
    let memory_after = get_memory_usage_ratio();
    let stats = GLOBAL_DEFRAGMENTER.get_stats().await;
    debug!("📊 证明器初始化完成，内存: {:.1}%, 缓存命中率: {:.1}%", 
          memory_after * 100.0,
          if stats.cache_hits + stats.cache_misses > 0 {
              (stats.cache_hits as f64 / (stats.cache_hits + stats.cache_misses) as f64) * 100.0
          } else { 0.0 });
    
    Ok(prover_arc)
}

/// 获取或创建内存优化的fib_input_initial证明器实例
pub async fn get_or_create_initial_prover() -> Result<Arc<Stwo<Local>>, ProverError> {
    // 快速路径：已初始化则直接返回
    if let Some(prover) = &*GLOBAL_PROVER_INITIAL.read().await {
        return Ok(prover.clone());
    }
    
    // 获取初始化锁（防止多线程同时初始化）
    let _guard = PROVER_INIT_LOCK.lock().await;
    // 再次检查以避免竞争条件
    if let Some(prover) = &*GLOBAL_PROVER_INITIAL.read().await {
        return Ok(prover.clone());
    }
    
    // 检查内存状态
    let memory_ratio = get_memory_usage_ratio();
    if memory_ratio > 0.90 {
        debug!("⚠️ 内存使用率过高 ({:.1}%)，执行清理...", memory_ratio * 100.0);
        perform_memory_cleanup();
    }
    
    // 初始化证明器
    let prover = get_initial_stwo_prover()
        .map_err(|e| ProverError::Stwo(format!("创建初始证明器失败: {}", e)))?;
    let prover_arc = Arc::new(prover);
    
    // 更新全局实例
    *GLOBAL_PROVER_INITIAL.write().await = Some(prover_arc.clone());
    
    Ok(prover_arc)
}

/// Proves a program locally with hardcoded inputs.
pub async fn prove_anonymously(
    environment: &Environment,
    client_id: String,
) -> Result<Proof, ProverError> {
    // Compute the 10th Fibonacci number using fib_input_initial
    // Input: (n=9, init_a=1, init_b=1)
    // This computes F(9) = 55 in the classic Fibonacci sequence starting with 1,1
    // Sequence: F(0)=1, F(1)=1, F(2)=2, F(3)=3, F(4)=5, F(5)=8, F(6)=13, F(7)=21, F(8)=34, F(9)=55
    let public_input: (u32, u32, u32) = (9, 1, 1);

    // 检查内存压力并在必要时清理
    if check_memory_pressure() {
        perform_memory_cleanup();
    }

    // 使用全局缓存的证明器
    let stwo_prover = get_or_create_initial_prover().await?;
    // 从Arc中借用值而不是移动
    let stwo_ref = stwo_prover.as_ref();
    let (view, proof) = stwo_ref
        .prove_with_input::<(), (u32, u32, u32)>(&(), &public_input)
        .map_err(|e| {
            ProverError::Stwo(format!(
                "Failed to run fib_input_initial prover (anonymous): {}",
                e
            ))
        })?;

    let exit_code = view.exit_code().map_err(|e| {
        ProverError::GuestProgram(format!("Failed to deserialize exit code: {}", e))
    })?;

    if exit_code != KnownExitCodes::ExitSuccess as u32 {
        return Err(ProverError::GuestProgram(format!(
            "Prover exited with non-zero exit code: {}",
            exit_code
        )));
    }

    // Send analytics event for anonymous proof - return analytics error but don't fail the proof
    if let Err(e) = track(
        "cli_proof_anon_v3".to_string(),
        json!({
            "program_name": "fib_input_initial",
            "public_input": public_input.0,
            "public_input_2": public_input.1,
            "public_input_3": public_input.2,
        }),
        environment,
        client_id,
    )
    .await
    {
        // Log locally but also return the analytics error so it can be classified and displayed
        debug!("Analytics tracking failed (non-critical): {}", e);
        return Err(ProverError::Analytics(e.to_string()));
    }

    Ok(proof)
}

/// Proves a program with a given node ID
pub async fn authenticated_proving(
    task: &Task,
    environment: &Environment,
    client_id: String,
) -> Result<Proof, ProverError> {
    // 检查内存压力并在必要时清理
    if check_memory_pressure() {
        perform_memory_cleanup();
    }
    
    let (view, proof, analytics_input) = match task.program_id.as_str() {
        "fast-fib" => {
            // fast-fib uses string inputs
            let input = get_string_public_input(task)?;
            // 使用全局缓存的证明器
            let stwo_prover = get_or_create_default_prover().await?;
            // 从Arc中借用值而不是移动
            let stwo_ref = stwo_prover.as_ref();
            let (view, proof) = stwo_ref
                .prove_with_input::<(), u32>(&(), &input)
                .map_err(|e| ProverError::Stwo(format!("Failed to run fast-fib prover: {}", e)))?;
            (view, proof, input)
        }
        "fib_input_initial" => {
            let inputs = get_triple_public_input(task)?;
            // 使用全局缓存的证明器
            let stwo_prover = get_or_create_initial_prover().await?;
            // 从Arc中借用值而不是移动
            let stwo_ref = stwo_prover.as_ref();
            let (view, proof) = stwo_ref
                .prove_with_input::<(), (u32, u32, u32)>(&(), &inputs)
                .map_err(|e| {
                    ProverError::Stwo(format!("Failed to run fib_input_initial prover: {}", e))
                })?;
            (view, proof, inputs.0)
        }
        _ => {
            return Err(ProverError::MalformedTask(format!(
                "Unsupported program ID: {}",
                task.program_id
            )));
        }
    };

    let exit_code = view.exit_code().map_err(|e| {
        ProverError::GuestProgram(format!("Failed to deserialize exit code: {}", e))
    })?;

    if exit_code != KnownExitCodes::ExitSuccess as u32 {
        return Err(ProverError::GuestProgram(format!(
            "Prover exited with non-zero exit code: {}",
            exit_code
        )));
    }

    // Send analytics event for authenticated proof
    let analytics_data = match task.program_id.as_str() {
        "fast-fib" => json!({
            "program_name": "fast-fib",
            "public_input": analytics_input,
            "task_id": task.task_id,
        }),
        "fib_input_initial" => {
            let inputs = get_triple_public_input(task)?;
            json!({
                "program_name": "fib_input_initial",
                "public_input": inputs.0,
                "public_input_2": inputs.1,
                "public_input_3": inputs.2,
                "task_id": task.task_id,
            })
        }
        _ => unreachable!(),
    };

    // Send analytics event for authenticated proof - return analytics error but don't fail the proof
    if let Err(e) = track(
        "cli_proof_node_v3".to_string(),
        analytics_data,
        environment,
        client_id,
    )
    .await
    {
        // Log locally but also return the analytics error so it can be classified and displayed
        debug!("Analytics tracking failed (non-critical): {}", e);
        return Err(ProverError::Analytics(e.to_string()));
    }

    Ok(proof)
}

fn get_string_public_input(task: &Task) -> Result<u32, ProverError> {
    // For fast-fib, just take the first byte as a u32 (how it worked before)
    if task.public_inputs.is_empty() {
        return Err(ProverError::MalformedTask(
            "Task public inputs are empty".to_string(),
        ));
    }
    Ok(task.public_inputs[0] as u32)
}

fn get_triple_public_input(task: &Task) -> Result<(u32, u32, u32), ProverError> {
    if task.public_inputs.len() < 12 {
        return Err(ProverError::MalformedTask(
            "Public inputs buffer too small, expected at least 12 bytes for three u32 values"
                .to_string(),
        ));
    }

    // Read all three u32 values (little-endian) from the buffer
    let mut bytes = [0u8; 4];

    bytes.copy_from_slice(&task.public_inputs[0..4]);
    let n = u32::from_le_bytes(bytes);

    bytes.copy_from_slice(&task.public_inputs[4..8]);
    let init_a = u32::from_le_bytes(bytes);

    bytes.copy_from_slice(&task.public_inputs[8..12]);
    let init_b = u32::from_le_bytes(bytes);

    Ok((n, init_a, init_b))
}

/// Create a Stwo prover for the default program.
pub fn get_default_stwo_prover() -> Result<Stwo<Local>, ProverError> {
    let elf_bytes = include_bytes!("../assets/fib_input");
    Stwo::<Local>::new_from_bytes(elf_bytes).map_err(|e| {
        let msg = format!("Failed to load fib_input guest program: {}", e);
        ProverError::Stwo(msg)
    })
}

/// Create a Stwo prover for the initial program.
pub fn get_initial_stwo_prover() -> Result<Stwo<Local>, ProverError> {
    let elf_bytes = include_bytes!("../assets/fib_input_initial");
    Stwo::<Local>::new_from_bytes(elf_bytes).map_err(|e| {
        let msg = format!("Failed to load fib_input_initial guest program: {}", e);
        ProverError::Stwo(msg)
    })
}

/// 获取全局内存碎片整理器的引用
pub fn get_defragmenter() -> Arc<MemoryDefragmenter> {
    GLOBAL_DEFRAGMENTER.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // The default Stwo prover should be created successfully.
    fn test_get_default_stwo_prover() {
        let prover = get_default_stwo_prover();
        match prover {
            Ok(_) => println!("Prover initialized successfully."),
            Err(e) => panic!("Failed to initialize prover: {}", e),
        }
    }

    #[tokio::test]
    // Proves a program with hardcoded inputs should succeed.
    async fn test_prove_anonymously() {
        let environment = Environment::Local;
        let client_id = "test_client_id".to_string();
        if let Err(e) = prove_anonymously(&environment, client_id).await {
            panic!("Failed to prove anonymously: {}", e);
        }
    }
}
