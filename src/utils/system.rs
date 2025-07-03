use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;
use log::debug;

// 导入系统模块，用于获取内存信息
use crate::system::{get_memory_info, process_memory_gb};

// 内存使用比率阈值 - 超过这个值会触发内存清理
const HIGH_MEMORY_THRESHOLD: f64 = 0.85;
const CRITICAL_MEMORY_THRESHOLD: f64 = 0.92;
const GC_COOL_DOWN_SECS: u64 = 60; // 避免太频繁触发内存清理

/// 检查系统内存压力
#[allow(dead_code)]
pub fn check_memory_pressure() -> bool {
    let (used_mb, total_mb) = get_memory_info();
    let ratio = used_mb as f64 / total_mb as f64;
    ratio > HIGH_MEMORY_THRESHOLD
}

/// 获取系统内存使用率
pub fn get_memory_usage_ratio() -> f64 {
    let (used_mb, total_mb) = get_memory_info();
    used_mb as f64 / total_mb as f64
}

/// 强制进行内存清理 - 调用垃圾回收并释放缓存
pub fn perform_memory_cleanup() {
    debug!("执行内存清理...");
    
    #[cfg(target_os = "linux")]
    {
        // 在Linux上使用libc的malloc_trim来释放未使用的内存
        // 这通常比标准的GC更有效
        unsafe {
            unsafe extern "C" {
            fn malloc_trim(pad: usize) -> i32;
        }
        let _ = malloc_trim(0);
        }
    }
    
    // 强制垃圾回收
    #[cfg(feature = "jemalloc")]
    {
        // 如果使用了jemalloc，则调用purge释放内存
        // 移除对私有模块的使用
        // use jemallocator::ffi::mallctl;
        // let _ = mallctl("arena.0.purge".as_ptr() as *const _, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0);
    }
    
    // 在所有平台上，触发一次大型内存分配和释放，帮助堆整理
    {
        // 分配和释放一些内存，促使分配器整理堆
        let size = 16 * 1024 * 1024; // 16 MB
        let mut big_vec = Vec::<u8>::with_capacity(size);
        big_vec.resize(size, 0);
        drop(big_vec);
    }
    
    // 手动请求垃圾回收
    #[cfg(not(target_os = "windows"))]
    {
        // 非Windows系统上调用malloc_trim
        unsafe {
            unsafe extern "C" {
            fn malloc_trim(pad: usize) -> i32;
        }
        let _ = malloc_trim(0);
        }
    }
}

/// 内存碎片整理器的结果统计
pub struct DefragmenterStats {
    pub cache_hits: u64,
    pub cache_misses: u64,
    #[allow(dead_code)]
    pub total_checks: u64,
    pub cleanups_performed: u64,
    pub bytes_freed: u64,
}

/// 内存碎片整理器结果
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