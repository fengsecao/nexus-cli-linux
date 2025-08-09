//! System information and performance measurements

use cfg_if::cfg_if;
use std::hint::black_box;
use std::process;
use std::sync::OnceLock;
use std::thread::available_parallelism;
use std::time::Instant;
use sysinfo::{CpuRefreshKind, RefreshKind, System};
use tokio::sync::Mutex as AsyncMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use log::debug;

const NUM_TESTS: u64 = 1_000_000;
const OPERATIONS_PER_ITERATION: u64 = 4; // sin, add, multiply, divide
const NUM_REPEATS: usize = 5; // Number of repeats to average the results

// Cache for flops measurement - only measure once per application run
static FLOPS_CACHE: OnceLock<f32> = OnceLock::new();

// 内存使用比率阈值 - 超过这个值会触发内存清理
const HIGH_MEMORY_THRESHOLD: f64 = 0.85;
const CRITICAL_MEMORY_THRESHOLD: f64 = 0.92;
const GC_COOL_DOWN_SECS: u64 = 60; // 避免太频繁触发内存清理

/// 内存碎片整理器的结果统计
#[derive(Debug)]
pub struct DefragmenterStats {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total_checks: u64,
    pub cleanups_performed: u64,
    pub bytes_freed: u64,
}

/// 内存碎片整理器结果
#[derive(Debug)]
pub struct DefragmentationResult {
    pub memory_before: f64,
    pub memory_after: f64,
    pub bytes_freed: u64,
    pub was_critical: bool,
}

impl DefragmentationResult {
    pub fn memory_freed_percentage(&self) -> f64 {
        if self.memory_before > 0.0 {
            ((self.memory_before - self.memory_after) / self.memory_before) * 100.0
        } else {
            0.0
        }
    }
}

/// 高级内存碎片整理器 - 提供智能内存清理和缓存字符串功能
#[derive(Debug)]
pub struct MemoryDefragmenter {
    last_gc_time: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    total_checks: AtomicU64,
    cleanups_performed: AtomicU64,
    bytes_freed: AtomicU64,
    is_defragmenting: AtomicBool,
    
    // 字符串缓存池 - 避免UI渲染期间的内存分配
    string_cache: Arc<AsyncMutex<Vec<String>>>,
}

impl MemoryDefragmenter {
    /// 创建新的内存碎片整理器
    pub fn new() -> Self {
        Self {
            last_gc_time: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            total_checks: AtomicU64::new(0),
            cleanups_performed: AtomicU64::new(0),
            bytes_freed: AtomicU64::new(0),
            is_defragmenting: AtomicBool::new(false),
            string_cache: Arc::new(AsyncMutex::new(Vec::with_capacity(32))),
        }
    }
    
    /// 检查是否应该进行内存碎片整理
    pub async fn should_defragment(&self) -> bool {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        
        // 避免并发清理
        if self.is_defragmenting.load(Ordering::Relaxed) {
            return false;
        }
        
        // 获取当前内存使用情况
        let memory_ratio = get_memory_usage_ratio();
        
        // 检查是否满足清理条件
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let last_gc = self.last_gc_time.load(Ordering::Relaxed);
        let time_since_last_gc = now - last_gc;
        
        if memory_ratio > CRITICAL_MEMORY_THRESHOLD {
            // 内存使用超过临界值，立即清理
            debug!("内存使用超过临界值 {:.1}%，触发立即清理", memory_ratio * 100.0);
            true
        } else if memory_ratio > HIGH_MEMORY_THRESHOLD && time_since_last_gc > GC_COOL_DOWN_SECS {
            // 内存使用超过高阈值且超过冷却时间
            debug!("内存使用超过阈值 {:.1}%，上次清理在{}秒前", 
                  memory_ratio * 100.0, time_since_last_gc);
            true
        } else {
            false
        }
    }
    
    /// 执行内存碎片整理
    pub async fn defragment(&self) -> DefragmentationResult {
        // 设置标志，避免并发清理
        if self.is_defragmenting.compare_exchange(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            // 已经有一个清理进程在运行
            return DefragmentationResult {
                memory_before: 0.0,
                memory_after: 0.0,
                bytes_freed: 0,
                was_critical: false,
            };
        }
        
        let memory_before = get_memory_usage_ratio();
        let process_memory_before = process_memory_gb();
        let is_critical = memory_before > CRITICAL_MEMORY_THRESHOLD;
        
        // 执行内存清理
        perform_memory_cleanup();
        
        // 更新统计信息
        self.cleanups_performed.fetch_add(1, Ordering::Relaxed);
        
        // 更新最后清理时间
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_gc_time.store(now, Ordering::Relaxed);
        
        // 给清理一点时间生效
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let memory_after = get_memory_usage_ratio();
        let process_memory_after = process_memory_gb();
        let bytes_freed = if process_memory_after < process_memory_before {
            ((process_memory_before - process_memory_after) * 1024.0 * 1024.0 * 1024.0) as u64
        } else {
            0
        };
        
        // 更新释放的字节数
        self.bytes_freed.fetch_add(bytes_freed, Ordering::Relaxed);
        
        // 重置状态
        self.is_defragmenting.store(false, Ordering::Release);
        
        DefragmentationResult {
            memory_before,
            memory_after,
            bytes_freed,
            was_critical: is_critical,
        }
    }
    
    /// 获取统计信息
    pub async fn get_stats(&self) -> DefragmenterStats {
        DefragmenterStats {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            total_checks: self.total_checks.load(Ordering::Relaxed),
            cleanups_performed: self.cleanups_performed.load(Ordering::Relaxed),
            bytes_freed: self.bytes_freed.load(Ordering::Relaxed),
        }
    }
    
    /// 从缓存池获取一个字符串
    pub async fn get_cached_string(&self, capacity: usize) -> String {
        let mut cache = self.string_cache.lock().await;
        if let Some(mut s) = cache.pop() {
            s.clear();
            s.shrink_to(capacity);
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            s
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
            String::with_capacity(capacity)
        }
    }
    
    /// 将字符串归还给缓存池
    pub async fn return_string(&self, s: String) {
        let mut cache = self.string_cache.lock().await;
        
        // 限制缓存大小，避免过度缓存
        if cache.len() < 100 {
            cache.push(s);
        }
    }
}

/// 检查系统内存压力
pub fn check_memory_pressure() -> bool {
    let (used_mb, total_mb) = get_system_memory_with_swap_mb();
    let ratio = used_mb as f64 / total_mb as f64;
    ratio > HIGH_MEMORY_THRESHOLD
}

/// 获取系统内存使用率
pub fn get_memory_usage_ratio() -> f64 {
    let (used_mb, total_mb) = get_system_memory_with_swap_mb();
    used_mb as f64 / total_mb as f64
}

/// 强制进行内存清理 - 调用垃圾回收并释放缓存
pub fn perform_memory_cleanup() {
    // 在所有平台上，触发一次大型内存分配和释放，帮助堆整理
    {
        // 分配和释放一些内存，促使分配器整理堆
        let size = 16 * 1024 * 1024; // 16 MB
        let mut big_vec = Vec::<u8>::with_capacity(size);
        big_vec.resize(size, 0);
        drop(big_vec);
    }
}

/// Get the number of logical cores available on the machine.
pub fn num_cores() -> usize {
    available_parallelism().map(|n| n.get()).unwrap_or(1) // Fallback to 1 if detection fails
}

/// Return (logical_cores, base_frequency_MHz).
/// `sysinfo` provides MHz on every supported OS.
fn cpu_stats() -> (u64, u64) {
    let mut sys =
        System::new_with_specifics(RefreshKind::nothing().with_cpu(CpuRefreshKind::everything()));
    // Wait a bit because CPU usage is based on diff.
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    // Refresh CPUs again to get actual value.
    sys.refresh_cpu_all();

    let logical_cores = available_parallelism().map(|n| n.get() as u64).unwrap_or(1);

    // `sysinfo` reports the *base* frequency of the first CPU package.
    // This avoids transient turbo clocks that overestimate peak GFLOP/s.
    let base_mhz = match sys.cpus().first() {
        Some(cpu) => cpu.frequency(),
        None => 0, // Fallback if no CPUs are detected
    };

    (logical_cores, base_mhz)
}

/// Detect the number of double-precision floating-point operations
/// a single **core** can theoretically complete per clock cycle,
/// based on the best SIMD extension available on *this* build target
/// (not at run-time).
fn flops_per_cycle_per_core() -> u32 {
    cfg_if! {
        if #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))] {
            // 512-bit vectors → 16 FP64 ops per FMA instruction
            16
        } else if #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))] {
            // 256-bit vectors → 8 FP64 ops
            8
        } else if #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))] {
            // 128-bit vectors → 4 FP64 ops
            4
        } else {
            // Conservative scalar fallback
            1
        }
    }
}

/// Estimate peak FLOPS (in GFLOP/s) from the number of prover threads and clock speed.
pub fn estimate_peak_gflops(num_provers: usize) -> f64 {
    let (_cores, mhz) = cpu_stats();
    let fpc = flops_per_cycle_per_core() as u64;

    // GFLOP/s = (cores * MHz * flops_per_cycle) / 1024
    (num_provers as u64 * mhz * fpc) as f64 / 1024.0
}

/// Measure actual FLOPS (in GFLOP/s) of this machine by running mathematical operations.
/// The result is cached after the first measurement, so subsequent calls return the cached value.
pub fn measure_gflops() -> f32 {
    *FLOPS_CACHE.get_or_init(|| {
        let num_cores: u64 = match available_parallelism() {
            Ok(cores) => cores.get() as u64,
            Err(_) => {
                eprintln!(
                    "Warning: Unable to determine the number of logical cores. Defaulting to 1."
                );
                1
            }
        };

        println!("Using {} logical cores for FLOPS measurement", num_cores);

        let avg_flops: f64 = (0..NUM_REPEATS)
            .map(|_| {
                let start = Instant::now();

                let total_flops: u64 = (0..num_cores)
                    .map(|_| {
                        let mut x: f64 = 1.0;
                        for _ in 0..NUM_TESTS {
                            x = black_box((x.sin() + 1.0) * 0.5 / 1.1);
                        }
                        NUM_TESTS * OPERATIONS_PER_ITERATION
                    })
                    .sum();

                total_flops as f64 / start.elapsed().as_secs_f64()
            })
            .sum::<f64>()
            / NUM_REPEATS as f64; // Average the FLOPS over all repeats

        (avg_flops / 1e9) as f32
    })
}

/// Get the memory usage of the current process and the total system memory, in MB.
pub fn get_memory_info() -> (i32, i32) {
    let mut system = System::new_all();
    system.refresh_all();

    let current_pid = process::id();
    let current_process = system
        .process(sysinfo::Pid::from(current_pid as usize))
        .expect("Failed to get current process");

    let program_memory_mb = bytes_to_mb_i32(current_process.memory());
    let total_memory_mb = bytes_to_mb_i32(system.total_memory());

    (program_memory_mb, total_memory_mb)
}

/// Get the system memory usage including swap, as (used_mb, total_mb).
pub fn get_system_memory_with_swap_mb() -> (i32, i32) {
    let mut sys = System::new();
    sys.refresh_memory();

    // sysinfo returns bytes (v0.30+)
    let total_ram = sys.total_memory();
    let used_ram = sys.used_memory();
    let total_swap = sys.total_swap();
    let used_swap = sys.used_swap();

    let total = total_ram.saturating_add(total_swap);
    let used = used_ram.saturating_add(used_swap);

    (bytes_to_mb_i32(used), bytes_to_mb_i32(total))
}

/// Total memory in GB of the machine.
pub fn total_memory_gb() -> f64 {
    let mut sys = System::new();
    sys.refresh_memory();
    let total_memory = sys.total_memory(); // bytes
    total_memory as f64 / 1024.0 / 1024.0 / 1024.0 // Convert to GB (binary)
}

/// Memory used by the current process, in GB.
#[allow(unused)]
pub fn process_memory_gb() -> f64 {
    let mut sys = System::new();
    sys.refresh_all();

    let current_pid = process::id();
    let current_process = sys
        .process(sysinfo::Pid::from(current_pid as usize))
        .expect("Failed to get current process");

    let memory = current_process.memory(); // bytes
    memory as f64 / 1024.0 / 1024.0 / 1024.0 // Convert to GB (binary)
}

// We encode the memory usage to i32 type at client
fn bytes_to_mb_i32(bytes: u64) -> i32 {
    // Convert bytes to MB (binary)
    (bytes as f64 / 1_048_576.0).round() as i32
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_estimate_peak_gflops() {
        let num_provers = 4; // Example number of prover threads
        let gflops = super::estimate_peak_gflops(num_provers);
        // println!("gflops = {}", gflops);
        assert!(gflops > 0.0, "Expected positive GFLOP/s estimate");
    }

    #[test]
    fn test_cpu_stats() {
        let (cores, mhz) = super::cpu_stats();
        assert!(cores > 0, "Expected at least one core");
        assert!(mhz > 0, "Expected non-zero MHz");
        // println!("Cores: {}, Base Frequency: {} MHz", cores, mhz);
    }
}
