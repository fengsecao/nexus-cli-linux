pub mod prover {
    // Queue sizes. Chosen to be larger than the tasks API page size (currently, 50)
    pub const TASK_QUEUE_SIZE: usize = 100;
    pub const EVENT_QUEUE_SIZE: usize = 100;
    pub const RESULT_QUEUE_SIZE: usize = 100;

    // Task fetching thresholds
    pub const BATCH_SIZE: usize = TASK_QUEUE_SIZE / 5; // Fetch this many tasks at once
    pub const LOW_WATER_MARK: usize = TASK_QUEUE_SIZE / 4; // Fetch new tasks when queue drops below this
    pub const MAX_404S_BEFORE_GIVING_UP: usize = 5; // Allow several 404s before stopping batch fetch
    pub const BACKOFF_DURATION: u64 = 30000; // 30 seconds
    pub const QUEUE_LOG_INTERVAL: u64 = 30000; // 30 seconds
    
    /// How long a task ID remains in the duplicate-prevention cache before expiring.
    pub const CACHE_EXPIRATION: u64 = 300000; // 5 minutes
}

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use rand::Rng;

// 默认429错误重试超时时间（秒）
const DEFAULT_RETRY_TIMEOUT: u64 = 30;

// 全局429错误重试超时时间
static RETRY_TIMEOUT: AtomicU64 = AtomicU64::new(DEFAULT_RETRY_TIMEOUT);
static INIT_ONCE: Once = Once::new();

/// 设置全局429错误重试超时时间
pub fn set_retry_timeout(timeout_seconds: u64) {
    RETRY_TIMEOUT.store(timeout_seconds, Ordering::SeqCst);
}

/// 获取429错误重试超时时间，带±10%的随机浮动
pub fn get_retry_timeout() -> u64 {
    let base_timeout = RETRY_TIMEOUT.load(Ordering::SeqCst);
    
    // 确保至少有1秒的超时时间
    if base_timeout <= 1 {
        return 1;
    }
    
    // 计算±10%的浮动范围
    let variation_range = (base_timeout as f64 * 0.1) as u64;
    if variation_range == 0 {
        return base_timeout;
    }
    
    // 生成-10%到+10%之间的随机变化
    let mut rng = rand::thread_rng();
    let variation = rng.gen_range(0..=variation_range * 2) as i64 - variation_range as i64;
    
    // 应用变化并确保结果为正数
    let result = base_timeout as i64 + variation;
    if result < 1 {
        1
    } else {
        result as u64
    }
}

/// 初始化常量
pub fn init() {
    INIT_ONCE.call_once(|| {
        // 初始化代码（如果需要）
    });
}
